<?php

namespace Kode\Jwt\Event;

use Kode\Jwt\Token\Payload;

class TokenRefreshed
{
    public function __construct(
        public readonly Payload $oldPayload,
        public readonly Payload $newPayload,
        public readonly string $oldToken,
        public readonly string $newToken,
        public readonly \DateTimeImmutable $refreshedAt
    ) {
    }

    /**
     * 获取用户ID
     */
    public function getUserId(): int
    {
        return $this->newPayload->uid;
    }

    /**
     * 获取平台
     */
    public function getPlatform(): string
    {
        return $this->newPayload->platform;
    }

    /**
     * 获取用户名
     */
    public function getUsername(): string
    {
        return $this->newPayload->username;
    }

    /**
     * 获取角色
     *
     * @return array<string>
     */
    public function getRoles(): array
    {
        return $this->newPayload->roles ?? [];
    }

    /**
     * 获取权限
     *
     * @return array<string>
     */
    public function getPermissions(): array
    {
        return $this->newPayload->perms ?? [];
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
        return $this->newPayload->custom ?? [];
    }

    /**
     * 获取旧Token的过期时间
     */
    public function getOldExpiresAt(): \DateTimeImmutable
    {
        return $this->refreshedAt->setTimestamp($this->oldPayload->exp);
    }

    /**
     * 获取新Token的过期时间
     */
    public function getNewExpiresAt(): \DateTimeImmutable
    {
        return $this->refreshedAt->setTimestamp($this->newPayload->exp);
    }

    /**
     * 获取新Token的剩余有效期（秒）
     */
    public function getNewTtl(): int
    {
        $now = new \DateTimeImmutable();
        $expiresAt = $this->getNewExpiresAt();

        if ($now > $expiresAt) {
            return 0;
        }

        return $expiresAt->getTimestamp() - $now->getTimestamp();
    }

    /**
     * 获取刷新时间间隔（秒）
     */
    public function getRefreshInterval(): int
    {
        return $this->newPayload->iat - $this->oldPayload->iat;
    }
}
