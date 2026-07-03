<?php

declare(strict_types=1);

namespace Kode\Jwt\Claim;

use Kode\Jwt\Contract\Arrayable;
use Kode\Jwt\Contract\Jsonable;
use Kode\Jwt\Exception\JwtException;

/**
 * OAuth2 / OIDC Scope 值对象（RFC 6749 §3.3 / RFC 6819）
 *
 * scope 以空格分隔的字符串形式存在于 Token 中，例如：
 *   "openid profile email offline_access"
 *
 * 本类提供：
 *  - 不可变集合语义（readonly class）
 *  - 解析/序列化为字符串与数组
 *  - 集合运算：has / hasAny / hasAll / intersect / diff
 *  - 与受支持 scope 列表的校验
 *
 * 安全设计：
 *  - 校验时区分大小写，避免 scope 名称混淆
 *  - 拒绝空字符串与重复 scope（去重）
 *  - 拒绝包含控制字符的 scope
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.3 RFC 6749 §3.3 - Access Token Scope
 */
final readonly class Scope implements Arrayable, Jsonable, \Countable
{
    /**
     * OIDC 标准 scope 集合
     */
    public const array OIDC_STANDARD_SCOPES = ['openid', 'profile', 'email', 'address', 'phone', 'offline_access'];

    /**
     * scope 合法字符集（RFC 6749 §3.3：x20 之外的 ASCII 可见字符）
     */
    private const string SCOPE_PATTERN = '#^[A-Za-z0-9._~:/-]+$#';

    /**
     * @param array<string> $scopes 已去重且已校验的 scope 列表
     */
    public function __construct(public array $scopes)
    {
    }

    /**
     * 从空格分隔的字符串构造
     *
     * @param string $scopeString 空格分隔的 scope 字符串
     * @return static
     * @throws JwtException 当包含非法字符时
     */
    public static function fromString(string $scopeString): static
    {
        if ($scopeString === '') {
            return new static([]);
        }

        $parts = preg_split('/\s+/', trim($scopeString)) ?: [];
        return self::fromArray($parts);
    }

    /**
     * 从数组构造
     *
     * @param array<string> $scopes
     * @return static
     * @throws JwtException 当包含非法字符时
     */
    #[\Override]
    public static function fromArray(array $scopes): static
    {
        $normalized = [];
        foreach ($scopes as $scope) {
            if (!is_string($scope) || $scope === '') {
                continue;
            }
            // 校验合法字符
            if (!preg_match(self::SCOPE_PATTERN, $scope)) {
                throw new JwtException("非法 scope 字符：{$scope}");
            }
            if (!in_array($scope, $normalized, true)) {
                $normalized[] = $scope;
            }
        }
        return new static($normalized);
    }

    /**
     * 从 JSON 字符串构造
     *
     * 支持 JSON 数组或 JSON 字符串（空格分隔）
     *
     * @param string $json
     * @return static
     * @throws JwtException
     */
    #[\Override]
    public static function fromJson(string $json): static
    {
        if (!json_validate($json)) {
            throw new JwtException('Scope JSON 解析失败：' . json_last_error_msg());
        }
        $data = json_decode($json, true);
        if (is_array($data)) {
            return self::fromArray($data);
        }
        if (is_string($data)) {
            return self::fromString($data);
        }
        throw new JwtException('Scope JSON 必须为数组或字符串');
    }

    /**
     * 判断是否包含指定 scope
     *
     * @param string $scope
     * @return bool
     */
    public function has(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    /**
     * 是否包含任一 scope
     *
     * @param array<string> $scopes
     * @return bool
     */
    public function hasAny(array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if (in_array($scope, $this->scopes, true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 是否包含全部 scope
     *
     * @param array<string> $scopes
     * @return bool
     */
    public function hasAll(array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if (!in_array($scope, $this->scopes, true)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 取交集（返回新实例）
     *
     * @param array<string> $scopes
     * @return static
     */
    public function intersect(array $scopes): static
    {
        return new static(array_values(array_intersect($this->scopes, $scopes)));
    }

    /**
     * 取差集（返回新实例）
     *
     * @param array<string> $scopes
     * @return static
     */
    public function diff(array $scopes): static
    {
        return new static(array_values(array_diff($this->scopes, $scopes)));
    }

    /**
     * 合并 scope（返回新实例，去重）
     *
     * @param array<string> $scopes
     * @return static
     */
    public function merge(array $scopes): static
    {
        return self::fromArray(array_merge($this->scopes, $scopes));
    }

    /**
     * 是否为空
     *
     * @return bool
     */
    public function isEmpty(): bool
    {
        return $this->scopes === [];
    }

    /**
     * 是否所有 scope 都在白名单内
     *
     * @param array<string> $allowedScopes 服务端允许的 scope 列表
     * @return bool
     */
    public function allAllowed(array $allowedScopes): bool
    {
        foreach ($this->scopes as $scope) {
            if (!in_array($scope, $allowedScopes, true)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 是否所有 scope 都是 OIDC 标准 scope
     *
     * @return bool
     */
    public function allStandard(): bool
    {
        return $this->allAllowed(self::OIDC_STANDARD_SCOPES);
    }

    /**
     * 转为空格分隔的字符串（RFC 6749 标准格式）
     *
     * @return string
     */
    public function toString(): string
    {
        return implode(' ', $this->scopes);
    }

    /**
     * 转为字符串（魔法方法，等价于 toString）
     */
    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * 转为数组
     *
     * @return array<string>
     */
    #[\Override]
    public function toArray(): array
    {
        return $this->scopes;
    }

    /**
     * 转为 JSON 字符串（数组形式）
     *
     * @param int $options
     * @return string
     */
    #[\Override]
    public function toJson(int $options = 0): string
    {
        $options = $options | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        $json = json_encode($this->scopes, $options);
        if ($json === false) {
            throw new JwtException('Scope JSON 编码失败：' . json_last_error_msg());
        }
        return $json;
    }

    /**
     * 计数器接口
     *
     * @return int
     */
    #[\Override]
    public function count(): int
    {
        return count($this->scopes);
    }
}
