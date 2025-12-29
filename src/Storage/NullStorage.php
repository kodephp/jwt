<?php

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\StorageInterface;

/**
 * 空存储实现
 *
 * 用于测试或禁用存储功能的场景，所有操作均为空操作
 */
class NullStorage implements StorageInterface
{
    /**
     * 设置键值对（空操作）
     *
     * @param string $key 键名
     * @param mixed $value 值
     * @param int $ttl 过期时间（秒）
     * @return bool
     */
    public function set(string $key, mixed $value, int $ttl = 0): bool
    {
        return true;
    }

    /**
     * 获取键对应的值（始终返回默认值）
     *
     * @param string $key 键名
     * @param mixed $default 默认值
     * @return mixed
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return $default;
    }

    /**
     * 删除键（空操作）
     *
     * @param string $key 键名
     * @return bool
     */
    public function delete(string $key): bool
    {
        return true;
    }

    /**
     * 检查键是否存在（始终返回false）
     *
     * @param string $key 键名
     * @return bool
     */
    public function has(string $key): bool
    {
        return false;
    }

    /**
     * 批量设置键值对（空操作）
     *
     * @param array<string, mixed> $values 键值对数组
     * @param int $ttl 过期时间（秒）
     * @return bool
     */
    public function setMultiple(array $values, int $ttl = 0): bool
    {
        return true;
    }

    /**
     * 批量获取键值对（始终返回默认值）
     *
     * @param array<string> $keys 键数组
     * @param mixed $default 默认值
     * @return array<string, mixed>
     */
    public function getMultiple(array $keys, mixed $default = null): array
    {
        return array_fill_keys($keys, $default);
    }

    /**
     * 批量删除键（空操作）
     *
     * @param array<string> $keys 键数组
     * @return bool
     */
    public function deleteMultiple(array $keys): bool
    {
        return true;
    }

    /**
     * 将键加入黑名单（空操作）
     *
     * @param string $jti Token ID
     * @param int $ttl 过期时间（秒）
     * @return bool
     */
    public function blacklist(string $jti, int $ttl = 3600): bool
    {
        return true;
    }

    /**
     * 检查键是否在黑名单中（始终返回false）
     *
     * @param string $jti Token ID
     * @return bool
     */
    public function isBlacklisted(string $jti): bool
    {
        return false;
    }

    /**
     * 清理过期项（空操作）
     *
     * @return bool
     */
    public function cleanExpired(): bool
    {
        return true;
    }

    /**
     * 获取存储统计信息
     *
     * @return array<string, mixed>
     */
    public function getStats(): array
    {
        return [
            'type' => 'null',
            'stats' => 'null storage always returns empty stats',
        ];
    }
}
