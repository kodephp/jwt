<?php

declare(strict_types=1);

namespace Kode\Jwt\KeyRotation;

use Kode\Jwt\Exception\JwtException;

/**
 * 密钥版本信息
 */
final readonly class KeyVersion
{
    public function __construct(
        public string $keyId,
        public string $key,
        public int $createdAt,
        public int $expiresAt,
        public bool $isActive = true,
        public bool $isPrimary = false
    ) {
    }

    /**
     * 检查密钥是否已过期
     */
    public function isExpired(): bool
    {
        return time() > $this->expiresAt;
    }

    /**
     * 检查密钥是否可用
     */
    public function isUsable(): bool
    {
        return $this->isActive && !$this->isExpired();
    }

    /**
     * 获取剩余有效时间
     */
    public function getRemainingTtl(): int
    {
        return max(0, $this->expiresAt - time());
    }

    /**
     * 从数组创建实例
     */
    public static function fromArray(array $data): self
    {
        return new self(
            keyId: $data['key_id'] ?? '',
            key: $data['key'] ?? '',
            createdAt: $data['created_at'] ?? time(),
            expiresAt: $data['expires_at'] ?? PHP_INT_MAX,
            isActive: $data['is_active'] ?? true,
            isPrimary: $data['is_primary'] ?? false
        );
    }

    /**
     * 转换为数组
     */
    public function toArray(): array
    {
        return [
            'key_id' => $this->keyId,
            'key' => $this->key,
            'created_at' => $this->createdAt,
            'expires_at' => $this->expiresAt,
            'is_active' => $this->isActive,
            'is_primary' => $this->isPrimary,
        ];
    }
}
