<?php

declare(strict_types=1);

namespace Kode\Jwt\Security\DPoP;

use Kode\Jwt\Enum\Algorithm;
use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Key\Jwk;
use Kode\Jwt\Key\JwkFactory;
use Kode\Jwt\Signature\Signer;

/**
 * DPoP 证明 JWT 构建器（RFC 9449 §4）
 *
 * 客户端在发起受保护资源请求前，用持有私钥生成一个 DPoP 证明 JWT：
 *  - header 内联公钥 JWK（typ=dpop+JWT）
 *  - payload 声明 htm / htu / iat，可选 ath（绑定 Access Token）/ nonce（服务端下发）
 *
 * 资源服务器据此确认请求方持有与 Access Token 绑定的密钥，抵御令牌重放/转发攻击。
 *
 * 安全设计：
 *  - 仅接受非对称算法（HS* 明确拒绝）：DPoP 依赖公私钥持有证明，对称算法无意义
 *  - 放入 header 的公钥取自私钥 toPublic()，绝不泄露私钥材料
 *  - 签名统一委托 Signer，支持 EdDSA / ES* / PS* / RS*
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9449 RFC 9449 - OAuth 2.0 Demonstrating Proof-of-Possession
 */
final class DPoPProofBuilder
{
    private readonly Jwk $publicJwk;

    /**
     * @param Algorithm $algorithm 签名算法（推荐 EdDSA / ES256）
     * @param string $privateKeyPem 私钥 PEM 或文件路径
     * @param string|null $kid 可选密钥标识（建议携带，便于服务端 JWKS 选择）
     */
    public function __construct(
        private readonly Algorithm $algorithm,
        private readonly string $privateKeyPem,
        private readonly ?string $kid = null,
    ) {
        if ($algorithm->isHmac()) {
            throw new JwtException('DPoP proof must use an asymmetric algorithm; HS* is not allowed');
        }
        // 私钥 → JWK → 公钥 JWK（仅公钥进入 header）
        $publicJwk = JwkFactory::fromPem($this->privateKeyPem)->toPublic();
        // 若显式指定 kid，将其同步到内联 JWK，便于服务端 JWKS 选择
        if ($this->kid !== null) {
            $publicJwk = Jwk::fromArray(array_merge($publicJwk->toArray(), ['kid' => $this->kid]));
        }
        $this->publicJwk = $publicJwk;
    }

    /**
     * 构建 DPoP 证明 JWT
     *
     * @param string $httpMethod HTTP 方法（GET/POST/...）
     * @param string $httpUri 请求 URI（含 scheme/host/path/query）
     * @param string|null $accessToken 绑定的 Access Token（用于计算 ath）
     * @param string|null $nonce 服务端下发的 nonce（防重放）
     * @param int|null $iat 签发时间（默认 time()）
     * @return string DPoP 证明 JWT
     * @throws JwtException
     */
    public function build(
        string $httpMethod,
        string $httpUri,
        ?string $accessToken = null,
        ?string $nonce = null,
        ?int $iat = null,
    ): string {
        $header = [
            'typ' => 'dpop+JWT',
            'alg' => $this->algorithm->value,
            'jwk' => $this->publicJwk->toArray(),
        ];
        if ($this->kid !== null) {
            $header['kid'] = $this->kid;
        }

        $iat ??= time();
        $payload = [
            'htm' => strtoupper($httpMethod),
            'htu' => DPoPProof::normalizeUri($httpUri),
            'iat' => $iat,
        ];
        if ($accessToken !== null) {
            $payload['ath'] = DPoPProof::accessTokenHash($accessToken);
        }
        if ($nonce !== null) {
            $payload['nonce'] = $nonce;
        }

        $headerB64 = DPoPProof::b64url((string) json_encode($header, JSON_UNESCAPED_SLASHES));
        $payloadB64 = DPoPProof::b64url((string) json_encode($payload, JSON_UNESCAPED_SLASHES));
        $data = "{$headerB64}.{$payloadB64}";

        $signature = Signer::sign($data, $this->algorithm, $this->privateKeyPem);
        $signatureB64 = DPoPProof::b64url($signature);

        return "{$headerB64}.{$payloadB64}.{$signatureB64}";
    }
}
