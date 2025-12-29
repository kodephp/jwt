<?php

namespace Kode\Jwt\Contract;

interface StorageInterface
{
    /**
     * 存储数据
     *
     * @param string $key
     * @param mixed $value
     * @param int $ttl 过期时间（秒）
     * @return bool
     */
    public function set(string $key, mixed $value, int $ttl = 3600): bool;

    /**
     * 获取数据
     *
     * @param string $key
     * @return mixed
     */
    public function get(string $key): mixed;

    /**
     * 检查数据是否存在
     *
     * @param string $key
     * @return bool
     */
    public function delete(string $key): bool;

    /**
     * 检查键是否存在
     *
     * @param string $key
     * @return bool
     */
    public function has(string $key): bool;

    /**
     * 批量设置键值对
     *
     * @param array<string, mixed> $values 键值对数组
     * @param int $ttl 过期时间（秒）
     * @return bool
     */
    public function setMultiple(array $values, int $ttl = 0): bool;

    /**
     * 批量获取键值对
     *
     * @param array<string> $keys 键数组
     * @param mixed $default 默认值
     * @return array<string|int, mixed>
     */
    public function getMultiple(array $keys, mixed $default = null): array;

    /**
     * 批量删除键
     *
     * @param array<string> $keys 键数组
     * @return bool
     */
    public function deleteMultiple(array $keys): bool;

    /**
     * 获取存储统计信息
     *
     * @return array<string, mixed>
     */
    public function getStats(): array;

    /**
     * 将Token加入黑名单
     *
     * @param string $jti
     * @param int $ttl 过期时间（秒）
     * @return bool
     */
    public function blacklist(string $jti, int $ttl = 3600): bool;

    /**
     * 检查Token是否在黑名单中
     *
     * @param string $jti
     * @return bool
     */
    public function isBlacklisted(string $jti): bool;

    /**
     * 清理过期数据
     *
     * @return bool
     */
    public function cleanExpired(): bool;
}
