<?php

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\StorageInterface;

class NullStorage implements StorageInterface
{
    /**
     * 设置键值对（空操作）
     */
    public function set(string $key, mixed $value, int $ttl = 0): bool
    {
        return true;
    }
    
    /**
     * 获取键对应的值（始终返回默认值）
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return $default;
    }
    
    /**
     * 删除键（空操作）
     */
    public function delete(string $key): bool
    {
        return true;
    }
    
    /**
     * 检查键是否存在（始终返回false）
     */
    public function has(string $key): bool
    {
        return false;
    }
    
    /**
     * 将键加入黑名单（空操作）
     */
    public function blacklist(string $jti, int $ttl = 3600): bool
    {
        return true;
    }
    
    /**
     * 检查键是否在黑名单中（始终返回false）
     */
    public function isBlacklisted(string $jti): bool
    {
        return false;
    }
    
    /**
     * 清理过期项（空操作）
     */
    public function cleanExpired(): int
    {
        return 0;
    }
}