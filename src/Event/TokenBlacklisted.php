<?php

namespace Kode\Jwt\Event;

use Kode\Jwt\Token\Payload;

class TokenBlacklisted
{
    public function __construct(
        public readonly Payload $payload,
        public readonly string $token,
        public readonly string $jti,
        public readonly \DateTimeImmutable $blacklistedAt,
        public readonly int $ttl
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
     */
    public function getRoles(): array
    {
        return $this->payload->roles ?? [];
    }
    
    /**
     * 获取权限
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
        return in_array($role, $this->getRoles());
    }
    
    /**
     * 检查是否有指定权限
     */
    public function hasPermission(string $permission): bool
    {
        return in_array($permission, $this->getPermissions());
    }
    
    /**
     * 获取自定义数据
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
        return $this->blacklistedAt->setTimestamp($this->payload->iat);
    }
    
    /**
     * 获取Token过期时间
     */
    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->blacklistedAt->setTimestamp($this->payload->exp);
    }
    
    /**
     * 获取Token生效时间
     */
    public function getNotBefore(): ?\DateTimeImmutable
    {
        if (isset($this->payload->nbf)) {
            return $this->blacklistedAt->setTimestamp($this->payload->nbf);
        }
        
        return null;
    }
    
    /**
     * 获取黑名单保留时长（秒）
     */
    public function getTtl(): int
    {
        return $this->ttl;
    }
    
    /**
     * 获取黑名单持续时间（秒）
     */
    public function getBlacklistedDuration(): int
    {
        $now = new \DateTimeImmutable();
        return $now->getTimestamp() - $this->blacklistedAt->getTimestamp();
    }
}