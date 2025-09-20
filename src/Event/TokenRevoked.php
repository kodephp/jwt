<?php

namespace Kode\Jwt\Event;

use Kode\Jwt\Token\Payload;

class TokenRevoked
{
    public function __construct(
        public readonly Payload $payload,
        public readonly string $token,
        public readonly string $jti,
        public readonly \DateTimeImmutable $revokedAt,
        public readonly ?string $reason = null
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
        return $this->revokedAt->setTimestamp($this->payload->iat);
    }
    
    /**
     * 获取Token过期时间
     */
    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->revokedAt->setTimestamp($this->payload->exp);
    }
    
    /**
     * 获取Token生效时间
     */
    public function getNotBefore(): ?\DateTimeImmutable
    {
        if (isset($this->payload->nbf)) {
            return $this->revokedAt->setTimestamp($this->payload->nbf);
        }
        
        return null;
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
    
    /**
     * 检查Token是否已过期
     */
    public function isExpired(): bool
    {
        $now = new \DateTimeImmutable();
        return $now > $this->getExpiresAt();
    }
}