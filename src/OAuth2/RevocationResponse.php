<?php

declare(strict_types=1);

namespace Kode\Jwt\OAuth2;

use Kode\Jwt\Contract\Arrayable;
use Kode\Jwt\Contract\Jsonable;
use Kode\Jwt\Exception\JwtException;

/**
 * Token 撤销端点响应（RFC 7009 §2.2）
 *
 * 撤销成功：HTTP 200 + 空响应体（RFC 7009 不泄露 Token 是否曾经存在）。
 * 撤销失败：HTTP 400 + error（unsupported_token_type / invalid_request 等）。
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7009 RFC 7009 - OAuth 2.0 Token Revocation
 */
final readonly class RevocationResponse implements Arrayable, Jsonable
{
    public function __construct(
        public bool $revoked,
        public ?string $error = null,
        public ?string $errorDescription = null,
    ) {
    }

    /**
     * 撤销成功（HTTP 200 + 空体）
     */
    public static function success(): self
    {
        return new self(revoked: true);
    }

    /**
     * 撤销失败（HTTP 400 + error）
     */
    public static function error(string $error, ?string $errorDescription = null): self
    {
        return new self(revoked: false, error: $error, errorDescription: $errorDescription);
    }

    /**
     * 是否撤销成功
     */
    public function isRevoked(): bool
    {
        return $this->revoked;
    }

    /**
     * 对应 HTTP 状态码
     */
    public function httpStatus(): int
    {
        return $this->revoked ? 200 : 400;
    }

    /**
     * 转为关联数组
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        if ($this->revoked) {
            return [];
        }

        $data = ['error' => $this->error];
        if ($this->errorDescription !== null) {
            $data['error_description'] = $this->errorDescription;
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
            throw new JwtException('Failed to encode revocation response: ' . json_last_error_msg());
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
        if (empty($data)) {
            return self::success();
        }

        return new self(
            revoked: (bool) ($data['revoked'] ?? false),
            error: isset($data['error']) ? (string) $data['error'] : null,
            errorDescription: isset($data['error_description']) ? (string) $data['error_description'] : null,
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
            throw new JwtException('Invalid revocation response JSON: ' . json_last_error_msg());
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new JwtException('Revocation response JSON must be an object');
        }

        return self::fromArray($data);
    }
}
