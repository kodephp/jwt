<?php

namespace Kode\Jwt\Event;

use Kode\Jwt\Token\Payload;

class TokenIssued
{
    public function __construct(
        public readonly Payload $payload,
        public readonly string $token,
        public readonly int $expiresIn,
        public readonly int $refreshTtl,
        public readonly \DateTimeImmutable $issuedAt
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
     * 获取过期时间
     */
    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->issuedAt->setTimestamp($this->payload->exp);
    }

    /**
     * 获取Token剩余有效期（秒）
     */
    public function getTtl(): int
    {
        $now = new \DateTimeImmutable();
        $expiresAt = $this->getExpiresAt();

        if ($now > $expiresAt) {
            return 0;
        }

        return $expiresAt->getTimestamp() - $now->getTimestamp();
    }
}
