<?php

declare(strict_types=1);

namespace Kode\Jwt\OpenId;

use Kode\Jwt\OAuth2\JwksResponse;
use Kode\Jwt\Exception\JwtException;

/**
 * OIDC / OAuth2 Discovery 端点发布器（RFC 8414）
 *
 * 将 {@see DiscoveryConfiguration} 以 JSON 格式发布到 /.well-known/openid-configuration
 * 或 /.well-known/oauth-authorization-server 端点，供依赖方（RP）自动发现授权服务器能力。
 *
 * 设计与 {@see \Kode\Jwt\OAuth2\JwksPublisher} 一致：
 *  - 与 PSR-7 / PSR-15 解耦，返回 {@link JwksResponse} 值对象
 *  - 支持 ETag / If-None-Match 协商缓存
 *  - 支持 Cache-Control 头
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8414 RFC 8414 - OAuth 2.0 Authorization Server Metadata
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html OIDC Discovery 1.0
 */
final class DiscoveryPublisher
{
    /**
     * 默认 Cache-Control max-age（秒），1 小时
     */
    private const int DEFAULT_MAX_AGE = 3600;

    /**
     * OIDC Discovery 标准端点路径
     */
    public const string OIDC_PATH = '/.well-known/openid-configuration';

    /**
     * OAuth2 Authorization Server Metadata 标准端点路径
     */
    public const string OAUTH_PATH = '/.well-known/oauth-authorization-server';

    /**
     * 构造函数
     *
     * @param DiscoveryConfiguration $configuration Discovery 元数据
     * @param int $maxAge Cache-Control max-age（秒），默认 3600
     */
    public function __construct(
        private DiscoveryConfiguration $configuration,
        private int $maxAge = self::DEFAULT_MAX_AGE,
    ) {
        if ($maxAge < 0) {
            throw new JwtException('DiscoveryPublisher maxAge 必须 >= 0');
        }
    }

    /**
     * 获取元数据配置
     *
     * @return DiscoveryConfiguration
     */
    public function getConfiguration(): DiscoveryConfiguration
    {
        return $this->configuration;
    }

    /**
     * 输出 Discovery JSON
     *
     * @param int $options json_encode 选项
     * @return string
     */
    public function toJson(int $options = 0): string
    {
        return $this->configuration->toJson($options);
    }

    /**
     * 计算强 ETag（基于 Discovery JSON 的 sha256）
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
     * 支持 If-None-Match 协商缓存：当客户端 ETag 匹配时返回 304。
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
        if (trim($clientHeader) === '*') {
            return true;
        }

        $serverTag = trim($serverEtag);
        foreach (explode(',', $clientHeader) as $candidate) {
            $candidate = trim($candidate);
            $candidateNormalized = preg_replace('/^W\//', '', $candidate) ?? $candidate;
            if ($candidateNormalized === $serverTag) {
                return true;
            }
        }
        return false;
    }

    /**
     * 替换 Discovery 配置（用于运行时更新）
     *
     * @param DiscoveryConfiguration $configuration
     * @return self
     */
    public function setConfiguration(DiscoveryConfiguration $configuration): self
    {
        $this->configuration = $configuration;
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
            throw new JwtException('DiscoveryPublisher maxAge 必须 >= 0');
        }
        $this->maxAge = $maxAge;
        return $this;
    }
}
