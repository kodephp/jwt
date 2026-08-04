<?php

declare(strict_types=1);

namespace Kode\Jwt\Security\DPoP;

use Kode\Jwt\Key\Jwk;

/**
 * 已验证的 DPoP 证明（RFC 9449）值对象
 *
 * 由 {@see DPoPValidator} 校验通过后构造，承载证明中的关键声明，
 * 供资源服务器比对请求方法/URI、绑定 Access Token 哈希（ath）、读取服务端 nonce 等。
 *
 * 同时承载一组共享工具方法（URI 规范化、ath 计算、base64url 编解码），
 * 供 {@see DPoPProofBuilder} 与 {@see DPoPValidator} 复用，避免逻辑分散。
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9449 RFC 9449 - OAuth 2.0 Demonstrating Proof-of-Possession
 */
final readonly class DPoPProof
{
    public function __construct(
        public Jwk $jwk,
        public string $jkt,
        public string $htm,
        public string $htu,
        public int $iat,
        public ?string $ath = null,
        public ?string $nonce = null,
    ) {
    }

    /**
     * 规范化 htu URI（RFC 9449 §4.2）
     *
     * 规则：scheme 与 host 转小写；保留 path 与 query；丢弃 fragment 与 userinfo；
     * 标准端口（http=80 / https=443）省略，非标准端口保留。
     */
    public static function normalizeUri(string $uri): string
    {
        $parts = parse_url($uri);
        if ($parts === false) {
            throw new \InvalidArgumentException("Invalid URI for DPoP htu: {$uri}");
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? 'https'));
        $host = strtolower((string) ($parts['host'] ?? ''));

        $port = '';
        if (isset($parts['port'])) {
            $defaultPort = $scheme === 'https' ? 443 : ($scheme === 'http' ? 80 : null);
            if ($defaultPort === null || (int) $parts['port'] !== $defaultPort) {
                $port = ':' . $parts['port'];
            }
        }

        $path = $parts['path'] ?? '/';
        $query = isset($parts['query']) ? '?' . $parts['query'] : '';

        return "{$scheme}://{$host}{$port}{$path}{$query}";
    }

    /**
     * 计算 Access Token 哈希 ath = BASE64URL(SHA256(ASCII(access_token)))
     */
    public static function accessTokenHash(string $accessToken): string
    {
        return self::b64url(hash('sha256', $accessToken, true));
    }

    /**
     * base64url 编码（无填充）
     */
    public static function b64url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * base64url 解码（兼容无填充）
     */
    public static function b64urlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder !== 0) {
            $data = str_pad($data, strlen($data) + (4 - $remainder), '=');
        }
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            throw new \InvalidArgumentException('Invalid base64url data in DPoP proof');
        }

        return $decoded;
    }
}
