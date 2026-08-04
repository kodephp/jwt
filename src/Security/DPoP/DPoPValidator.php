<?php

declare(strict_types=1);

namespace Kode\Jwt\Security\DPoP;

use Kode\Jwt\Enum\Algorithm;
use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Key\Jwk;
use Kode\Jwt\Key\KeyConverter;
use Kode\Jwt\Signature\Signer;

/**
 * DPoP 证明校验器（RFC 9449 §4.3 / §6）
 *
 * 资源服务器在收到 DPoP 保护的请求时，校验证明 JWT：
 *  1. 结构正确、typ=dpop+JWT、算法为非对称
 *  2. 用 header 内联 JWK 验签通过
 *  3. htm 匹配请求方法、htu 匹配（规范化后）请求 URI
 *  4. iat 落在新鲜度窗口内（默认 300s）
 *  5. 若服务端要求 nonce / 绑定 ath，则必须一致
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9449 RFC 9449 - OAuth 2.0 Demonstrating Proof-of-Possession
 */
final class DPoPValidator
{
    private const string TYP = 'dpop+JWT';
    private const int DEFAULT_MAX_AGE = 300;

    public function __construct(
        private readonly int $maxAge = self::DEFAULT_MAX_AGE,
        private readonly ?string $expectedNonce = null,
        private readonly ?string $expectedAth = null,
    ) {
    }

    /**
     * 校验 DPoP 证明
     *
     * @param string $proofJwt DPoP 证明 JWT
     * @param string $httpMethod 当前请求的 HTTP 方法
     * @param string $httpUri 当前请求的 URI（会被规范化后与 htu 比较）
     * @return DPoPProof 校验通过后的证明值对象
     * @throws JwtException 校验任一环节失败时抛出
     */
    public function validate(string $proofJwt, string $httpMethod, string $httpUri): DPoPProof
    {
        $parts = explode('.', $proofJwt);
        if (count($parts) !== 3) {
            throw new JwtException('Malformed DPoP proof JWT: expected 3 segments');
        }
        [$headerB64, $payloadB64, $sigB64] = $parts;

        $header = json_decode(DPoPProof::b64urlDecode($headerB64), true);
        $payload = json_decode(DPoPProof::b64urlDecode($payloadB64), true);
        if (!is_array($header) || !is_array($payload)) {
            throw new JwtException('Invalid DPoP proof encoding');
        }

        // 1. typ 固定
        if (($header['typ'] ?? null) !== self::TYP) {
            throw new JwtException('DPoP proof must have typ=dpop+JWT');
        }

        // 2. 算法须为非对称
        $algorithm = Algorithm::tryFromName((string) ($header['alg'] ?? ''));
        if ($algorithm === null || $algorithm->isHmac()) {
            throw new JwtException('DPoP proof requires an asymmetric algorithm');
        }

        // 3. header 必须内联 jwk 且为非对称公钥
        if (!isset($header['jwk']) || !is_array($header['jwk'])) {
            throw new JwtException('DPoP proof header must contain a jwk');
        }
        $jwk = Jwk::fromArray($header['jwk']);
        if (!$jwk->isAsymmetric()) {
            throw new JwtException('DPoP proof jwk must be an asymmetric key');
        }
        $jkt = $jwk->toPublic()->thumbprint('sha256');

        // 4. 验签
        $publicPem = KeyConverter::jwkToPem($jwk->toPublic());
        $signature = DPoPProof::b64urlDecode($sigB64);
        if (!Signer::verify("{$headerB64}.{$payloadB64}", $signature, $algorithm, $publicPem)) {
            throw new JwtException('DPoP proof signature verification failed');
        }

        // 5. htm 匹配请求方法
        $htm = strtoupper($httpMethod);
        if (($payload['htm'] ?? null) !== $htm) {
            throw new JwtException('DPoP proof htm does not match the request method');
        }

        // 6. htu 匹配（规范化后）
        $expectedHtu = DPoPProof::normalizeUri($httpUri);
        if (($payload['htu'] ?? null) !== $expectedHtu) {
            throw new JwtException('DPoP proof htu does not match the request URI');
        }

        // 7. iat 新鲜度
        $iat = (int) ($payload['iat'] ?? 0);
        $now = time();
        if ($iat <= 0 || $iat > $now + 30 || ($now - $iat) > $this->maxAge) {
            throw new JwtException('DPoP proof iat is outside the allowed freshness window');
        }

        // 8. nonce（若服务端要求）
        $nonce = isset($payload['nonce']) ? (string) $payload['nonce'] : null;
        if ($this->expectedNonce !== null && $nonce !== $this->expectedNonce) {
            throw new JwtException('DPoP proof nonce does not match the expected server nonce');
        }

        // 9. ath（若绑定 Access Token）
        $ath = isset($payload['ath']) ? (string) $payload['ath'] : null;
        if ($this->expectedAth !== null && $ath !== $this->expectedAth) {
            throw new JwtException('DPoP proof ath does not match the bound access token');
        }

        return new DPoPProof(
            jwk: $jwk,
            jkt: $jkt,
            htm: (string) $payload['htm'],
            htu: (string) $payload['htu'],
            iat: $iat,
            ath: $ath,
            nonce: $nonce,
        );
    }
}
