<?php

declare(strict_types=1);

namespace Kode\Jwt\Contract;

/**
 * 存储驱动接口
 *
 * 所有存储后端（Redis、Memory、File、Apcu、Memcached、Database 等）都应实现该接口。
 *
 * 设计原则：
 * 1. 基础 CRUD（set/get/delete/has/multiple）与 Token 生命周期方法（blacklist/cleanExpired）
 *    是必选能力，所有实现必须提供。
 * 2. SSO / 防重放 / 用户活跃 Token 列表等高级能力，参考 {@see SsoStorageInterface}，
 *    通过 `instanceof` 进行能力探测，避免对不支持的实现造成不必要的硬性约束。
 */
interface StorageInterface
{
    /**
     * 设置键值
     *
     * @param string $key 键名
     * @param mixed  $value 值
     * @param int    $ttl 过期时间（秒），0 表示永不过期
     * @return bool 是否成功
     */
    public function set(string $key, mixed $value, int $ttl = 0): bool;

    /**
     * 获取键值
     *
     * @param string $key 键名
     * @param mixed  $default 键不存在时的默认值
     * @return mixed
     */
    public function get(string $key, mixed $default = null): mixed;

    /**
     * 删除键
     */
    public function delete(string $key): bool;

    /**
     * 判断键是否存在
     */
    public function has(string $key): bool;

    /**
     * 批量设置
     *
     * @param array<string, mixed> $values 键值映射
     * @param int $ttl 过期时间（秒）
     * @return bool 是否全部成功
     */
    public function setMultiple(array $values, int $ttl = 0): bool;

    /**
     * 批量获取
     *
     * @param array<string> $keys 键列表
     * @param mixed $default 缺省值
     * @return array<string, mixed>
     */
    public function getMultiple(array $keys, mixed $default = null): array;

    /**
     * 批量删除
     */
    public function deleteMultiple(array $keys): bool;

    /**
     * 获取存储统计信息
     *
     * @return array<string, int|float|array<string, mixed>>
     */
    public function getStats(): array;

    /**
     * 将 JTI 加入黑名单
     */
    public function blacklist(string $jti, int $ttl = 3600): bool;

    /**
     * 判断 JTI 是否在黑名单中
     */
    public function isBlacklisted(string $jti): bool;

    /**
     * 清理过期数据
     *
     * @return bool|int
     */
    public function cleanExpired(): bool|int;

    /**
     * 延长键的过期时间
     */
    public function touch(string $key, int $ttl): bool;

    /**
     * 获取键的剩余过期时间（秒）
     *
     * @return int 剩余秒数，-2 表示键不存在，-1 表示永不过期
     */
    public function getRemainingTtl(string $key): int;

    /**
     * 清空存储
     */
    public function clear(): bool;
}
