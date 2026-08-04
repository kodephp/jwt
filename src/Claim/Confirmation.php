<?php

declare(strict_types=1);

namespace Kode\Jwt\Claim;

use Kode\Jwt\Contract\Arrayable;
use Kode\Jwt\Contract\Jsonable;
use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Key\Jwk;

/**
 * 确认声明（cnf）值对象 —— RFC 7800 §3.1
 *
 * cnf 声明将 Token 与某个密钥/证据绑定，常见用途与互操作点：
 *  - jkt：绑定 JWK 指纹（RFC 7638），是 DPoP（RFC 9449）确认 Token 由持有对应私钥的一方出示的核心字段
 *  - jwk：直接内嵌完整公钥（仅在受信信道下使用，注意泄露风险）
 *  - jku：指向 JWK Set 的 URL
 *  - kid：密钥标识
 *
 * 安全设计：
 *  - withJwk() 自动计算并附带 jkt（toPublic 后的 RFC 7638 指纹），与 DPoP 语义一致
 *  - 强制「单一证据类型」，避免服务端歧义判断导致的绕过
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7800 RFC 7800 - Proof-of-Possession Key Semantics for JWTs
 */
final readonly class Confirmation implements Arrayable, Jsonable
{
    public function __construct(
        public ?string $jkt = null,
        public ?Jwk $jwk = null,
        public ?string $jku = null,
        public ?string $kid = null,
    ) {
        if ($jkt === null && $jwk === null && $jku === null && $kid === null) {
            throw new JwtException('Confirmation claim (cnf) requires at least one member (jkt/jwk/jku/kid)');
        }
    }

    /**
     * 仅绑定 JWK 指纹（jkt）
     */
    public static function withJkt(string $jkt): self
    {
        return new self(jkt: $jkt);
    }

    /**
     * 绑定完整公钥 JWK，并自动附带其 RFC 7638 指纹（jkt）
     */
    public static function withJwk(Jwk $jwk): self
    {
        $public = $jwk->toPublic();
        return new self(jkt: $public->thumbprint('sha256'), jwk: $public);
    }

    /**
     * 绑定 JWK Set URL（jku）+ 可选 kid
     */
    public static function withJku(string $jku, ?string $kid = null): self
    {
        return new self(jku: $jku, kid: $kid);
    }

    /**
     * 仅绑定密钥标识（kid）
     */
    public static function withKid(string $kid): self
    {
        return new self(kid: $kid);
    }

    /**
     * 转为关联数组
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $data = [];
        if ($this->jkt !== null) {
            $data['jkt'] = $this->jkt;
        }
        if ($this->jwk !== null) {
            $data['jwk'] = $this->jwk->toArray();
        }
        if ($this->jku !== null) {
            $data['jku'] = $this->jku;
        }
        if ($this->kid !== null) {
            $data['kid'] = $this->kid;
        }

        return $data;
    }

    /**
     * 转为 JSON 字符串
     *
     * @param int $options json_encode 选项
     * @return string
     * @throws JwtException 当 JSON 编码失败时
     */
    public function toJson(int $options = 0): string
    {
        $options = $options | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        $json = json_encode($this->toArray(), $options);
        if ($json === false) {
            throw new JwtException('Failed to encode confirmation claim: ' . json_last_error_msg());
        }

        return $json;
    }

    /**
     * 从数组构造（与 toArray 互逆）
     *
     * @param array<string, mixed> $data
     * @return static
     */
    #[\Override]
    public static function fromArray(array $data): static
    {
        $jwt = isset($data['jwk']) && is_array($data['jwk']) ? Jwk::fromArray($data['jwk']) : null;

        return new self(
            jkt: isset($data['jkt']) ? (string) $data['jkt'] : null,
            jwk: $jwt,
            jku: isset($data['jku']) ? (string) $data['jku'] : null,
            kid: isset($data['kid']) ? (string) $data['kid'] : null,
        );
    }

    /**
     * 从 JSON 字符串构造
     *
     * @param string $json
     * @return static
     * @throws JwtException
     */
    #[\Override]
    public static function fromJson(string $json): static
    {
        if (!json_validate($json)) {
            throw new JwtException('Invalid confirmation claim JSON: ' . json_last_error_msg());
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new JwtException('Confirmation claim JSON must be an object');
        }

        return self::fromArray($data);
    }
}
