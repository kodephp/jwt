<?php

declare(strict_types=1);

namespace Kode\Jwt\OAuth2;

use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Key\JwkSet;

/**
 * JWKS 端点发布器（RFC 7517 §5 / RFC 8414 jwks_uri）
 *
 * 将本地持有的 JWK Set 以标准 JSON 格式发布，供 OAuth2 资源服务器 /
 * OpenID Connect 依赖方通过 `jwks_uri` 拉取公钥用于验签。
 *
 * 安全设计：
 *  - 永远只输出公开 JWK（自动调用 `JwkSet::toPublic()` 剥离私钥参数）
 *  - 提供 ETag 与 Cache-Control 头，避免资源服务器高频拉取
 *  - 支持 `If-None-Match` 304 响应，降低带宽消耗
 *
 * 与 PSR-7 / PSR-15 解耦：返回 `JwksResponse` 值对象，由上层框架适配为
 * Laravel Response / Hyperf Response / 原生 header() 调用。
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7517#section-5 RFC 7517 §5 - JWK Set
 * @see https://datatracker.ietf.org/doc/html/rfc8414#section-2 RFC 8414 - jwks_uri
 */
final class JwksPublisher
{
    /**
     * 默认 Cache-Control max-age（秒），1 小时
     */
    private const int DEFAULT_MAX_AGE = 3600;

    /**
     * 构造函数
     *
     * @param JwkSet $jwkSet 待发布的 JWK Set（可包含私钥，发布时会自动剥离）
     * @param int $maxAge Cache-Control max-age（秒），默认 3600
     */
    public function __construct(
        private JwkSet $jwkSet,
        private int $maxAge = self::DEFAULT_MAX_AGE,
    ) {
        if ($maxAge < 0) {
            throw new JwtException('JwksPublisher maxAge must be >= 0');
        }
    }

    /**
     * 获取已发布的 JWK Set（自动剥离私钥参数）
     *
     * @return JwkSet
     */
    public function getJwks(): JwkSet
    {
        return $this->jwkSet->toPublic();
    }

    /**
     * 输出 JWKS JSON
     *
     * @param int $options json_encode 选项
     * @return string
     */
    public function toJson(int $options = 0): string
    {
        return $this->getJwks()->toJson($options);
    }

    /**
     * 计算强 ETag（基于公开 JWK Set JSON 的 sha256）
     *
     * @return string 形如 '"a1b2c3..."'
     */
    public function getEtag(): string
    {
        return '"' . hash('sha256', $this->toJson()) . '"';
    }

    /**
     * 返回 Cache-Control 头值
     *
     * @return string 形如 "public, max-age=3600"
     */
    public function getCacheControl(): string
    {
        return 'public, max-age=' . $this->maxAge;
    }

    /**
     * 处理 HTTP 请求并返回响应
     *
     * 支持 `If-None-Match` 协商缓存：当客户端 ETag 匹配时返回 304。
     *
     * @param array<string, string> $requestHeaders 请求头（键小写化，如 ['if-none-match' => '...']）
     * @return JwksResponse
     */
    public function handle(array $requestHeaders = []): JwksResponse
    {
        $etag = $this->getEtag();
        $headers = [
            'Content-Type'  => 'application/json; charset=UTF-8',
            'Cache-Control' => $this->getCacheControl(),
            'ETag'          => $etag,
        ];

        // 协商缓存：If-None-Match 匹配则返回 304
        $inm = $requestHeaders['if-none-match'] ?? '';
        if ($inm !== '' && $this->etagMatches($inm, $etag)) {
            return new JwksResponse(status: 304, headers: $headers, body: '');
        }

        return new JwksResponse(status: 200, headers: $headers, body: $this->toJson());
    }

    /**
     * ETag 匹配比较（支持弱 ETag 与通配符）
     *
     * @param string $clientHeader 客户端 If-None-Match 头值
     * @param string $serverEtag 服务端 ETag
     * @return bool
     */
    private function etagMatches(string $clientHeader, string $serverEtag): bool
    {
        // 通配符 *
        if (trim($clientHeader) === '*') {
            return true;
        }

        $serverTag = trim($serverEtag);
        foreach (explode(',', $clientHeader) as $candidate) {
            $candidate = trim($candidate);

            // 弱 ETag 比较：W/"abc" 与 "abc" 视为匹配
            $candidateNormalized = preg_replace('/^W\//', '', $candidate) ?? $candidate;
            if ($candidateNormalized === $serverTag) {
                return true;
            }
        }
        return false;
    }

    /**
     * 设置新的 JWK Set（用于密钥轮换后更新发布器）
     *
     * @param JwkSet $jwkSet
     * @return self
     */
    public function setJwkSet(JwkSet $jwkSet): self
    {
        $this->jwkSet = $jwkSet;
        return $this;
    }

    /**
     * 设置 Cache-Control max-age
     *
     * @param int $maxAge
     * @return self
     */
    public function setMaxAge(int $maxAge): self
    {
        if ($maxAge < 0) {
            throw new JwtException('JwksPublisher maxAge must be >= 0');
        }
        $this->maxAge = $maxAge;
        return $this;
    }
}
