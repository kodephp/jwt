<?php

declare(strict_types=1);

namespace Kode\Jwt\OAuth2;

/**
 * JWKS 端点响应值对象
 *
 * 与 PSR-7 解耦：仅承载 status / headers / body 三元组，
 * 由上层框架适配为对应的 Response 对象。
 *
 * @see JwksPublisher::handle()
 */
final readonly class JwksResponse
{
    /**
     * 构造函数
     *
     * @param int $status HTTP 状态码（200 / 304）
     * @param array<string, string> $headers 响应头
     * @param string $body 响应体（304 时为空字符串）
     */
    public function __construct(
        public int $status,
        public array $headers,
        public string $body,
    ) {
    }

    /**
     * 是否为 304 Not Modified
     *
     * @return bool
     */
    public function isNotModified(): bool
    {
        return $this->status === 304;
    }

    /**
     * 是否为 200 OK
     *
     * @return bool
     */
    public function isOk(): bool
    {
        return $this->status === 200;
    }
}
