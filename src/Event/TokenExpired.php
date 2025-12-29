<?php

namespace Kode\Jwt\Event;

use Kode\Jwt\Token\Payload;

class TokenExpired
{
    public function __construct(
        public readonly Payload $payload,
        public readonly string $token,
        public readonly \DateTimeImmutable $expiredAt,
        public readonly bool $isRefreshable
    ) {
    }

    /**
     * 获取用户ID
     */
    public function getUserId(): int
    {
        return $this->payload->uid;
    }

    /**
     * 获取平台
     */
    public function getPlatform(): string
    {
        return $this->payload->platform;
    }

    /**
     * 获取用户名
     */
    public function getUsername(): string
    {
        return $this->payload->username;
    }

    /**
     * 获取角色
     *
     * @return array<string>
     */
    public function getRoles(): array
    {
        return $this->payload->roles ?? [];
    }

    /**
     * 获取权限
     *
     * @return array<string>
     */
    public function getPermissions(): array
    {
        return $this->payload->perms ?? [];
    }

    /**
     * 检查是否有指定角色
     */
    public function hasRole(string $role): bool
    {
        return in_array($role, $this->getRoles(), true);
    }

    /**
     * 检查是否有指定权限
     */
    public function hasPermission(string $permission): bool
    {
        return in_array($permission, $this->getPermissions(), true);
    }

    /**
     * 获取自定义数据
     *
     * @return array<string, mixed>
     */
    public function getCustomData(): array
    {
        return $this->payload->custom ?? [];
    }

    /**
     * 获取Token签发时间
     */
    public function getIssuedAt(): \DateTimeImmutable
    {
        return $this->expiredAt->setTimestamp($this->payload->iat);
    }

    /**
     * 获取Token过期时间
     */
    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiredAt->setTimestamp($this->payload->exp);
    }

    /**
     * 获取Token生效时间
     */
    public function getNotBefore(): ?\DateTimeImmutable
    {
        $nbf = $this->payload->custom['nbf'] ?? null;
        if (isset($nbf) && is_int($nbf)) {
            return $this->expiredAt->setTimestamp($nbf);
        }

        return null;
    }

    /**
     * 检查Token是否可刷新
     */
    public function isRefreshable(): bool
    {
        return $this->isRefreshable;
    }

    /**
     * 获取过期时长（秒）
     */
    public function getExpiredDuration(): int
    {
        $now = new \DateTimeImmutable();
        return $now->getTimestamp() - $this->getExpiresAt()->getTimestamp();
    }
}
