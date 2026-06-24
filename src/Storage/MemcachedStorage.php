<?php

declare(strict_types=1);

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\SsoStorageInterface;
use Kode\Jwt\Contract\StorageInterface;
use Memcached;

/**
 * Memcached 存储实现
 *
 * 使用 Memcached 作为 JWT 存储后端，适用于分布式缓存场景
 */
class MemcachedStorage implements SsoStorageInterface
{
    /** @var Memcached Memcached 实例 */
    protected Memcached $memcached;
    /** @var string 键前缀 */
    protected string $prefix;
    /** @var array<string, mixed> 配置数组 */
    protected array $config;

    /**
     * 构造函数
     *
     * @param array<string, mixed> $config 配置数组
     */
    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->prefix = $config['prefix'] ?? 'kode:jwt:';

        $this->connect();
    }

    /**
     * 连接 Memcached
     */
    protected function connect(): void
    {
        $this->memcached = new Memcached();

        // 添加服务器
        $servers = $this->config['servers'] ?? [['127.0.0.1', 11211, 100]];

        // 将关联数组配置转换为索引数组，满足 Memcached::addServers 的参数要求
        $normalizedServers = [];
        foreach ($servers as $server) {
            if (isset($server['host'])) {
                $normalizedServers[] = [
                    $server['host'],
                    $server['port'] ?? 11211,
                    $server['weight'] ?? 0,
                ];
            } else {
                $normalizedServers[] = [
                    $server[0] ?? '127.0.0.1',
                    $server[1] ?? 11211,
                    $server[2] ?? 0,
                ];
            }
        }

        $this->memcached->addServers($normalizedServers);

        // 设置选项
        if (isset($this->config['options'])) {
            foreach ($this->config['options'] as $option => $value) {
                $this->memcached->setOption($option, $value);
            }
        }
    }

    /**
     * 获取带前缀的键名
     */
    protected function getKey(string $key): string
    {
        return $this->prefix . $key;
    }

    /**
     * 获取 TTL 元数据键名
     */
    protected function getMetaTtlKey(string $key): string
    {
        return $this->getKey("{$key}:meta_ttl");
    }

    /**
     * 设置键值对
     */
    public function set(string $key, mixed $value, int $ttl = 0): bool
    {
        $prefixedKey = $this->getKey($key);
        $result = $this->memcached->set($prefixedKey, $value, $ttl);

        // 当设置了过期时间时，额外存储 meta TTL 键记录过期时间戳
        if ($result && $ttl > 0) {
            $metaKey = $this->getMetaTtlKey($key);
            $this->memcached->set($metaKey, time() + $ttl, $ttl);
        }

        return $result;
    }

    /**
     * 获取键对应的值
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $prefixedKey = $this->getKey($key);
        $value = $this->memcached->get($prefixedKey);

        // 检查操作是否成功，未成功则返回默认值
        if ($this->memcached->getResultCode() !== Memcached::RES_SUCCESS) {
            return $default;
        }

        return $value;
    }

    /**
     * 删除键
     */
    public function delete(string $key): bool
    {
        $prefixedKey = $this->getKey($key);
        $result = $this->memcached->delete($prefixedKey);

        // 同时删除 meta TTL 键
        $this->memcached->delete($this->getMetaTtlKey($key));

        return $result;
    }

    /**
     * 检查键是否存在
     */
    public function has(string $key): bool
    {
        $prefixedKey = $this->getKey($key);
        $this->memcached->get($prefixedKey);

        return $this->memcached->getResultCode() === Memcached::RES_SUCCESS;
    }

    /**
     * 将键加入黑名单
     */
    public function blacklist(string $jti, int $ttl = 3600): bool
    {
        $key = $this->getKey("blacklist:{$jti}");
        return $this->memcached->set($key, true, $ttl);
    }

    /**
     * 检查键是否在黑名单中
     */
    public function isBlacklisted(string $jti): bool
    {
        $key = $this->getKey("blacklist:{$jti}");
        $this->memcached->get($key);

        return $this->memcached->getResultCode() === Memcached::RES_SUCCESS;
    }

    /**
     * 清理过期项（Memcached 会自动清理过期项）
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
            'type' => 'memcached',
            'prefix' => $this->prefix,
            'connected' => true,
        ];
    }

    /**
     * 批量设置键值对
     *
     * @param array<string, mixed> $values 键值对数组
     * @param int $ttl 过期时间（秒）
     * @return bool
     */
    public function setMultiple(array $values, int $ttl = 0): bool
    {
        foreach ($values as $key => $value) {
            if (!$this->set($key, $value, $ttl)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 批量获取键值对
     *
     * @param array<string> $keys 键数组
     * @param mixed $default 默认值
     * @return array<string, mixed>
     */
    public function getMultiple(array $keys, mixed $default = null): array
    {
        $results = [];
        foreach ($keys as $key) {
            $results[$key] = $this->get($key, $default);
        }
        return $results;
    }

    /**
     * 批量删除键
     *
     * @param array<string> $keys 键数组
     * @return bool
     */
    public function deleteMultiple(array $keys): bool
    {
        foreach ($keys as $key) {
            if (!$this->delete($key)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 延长键的过期时间
     *
     * @param string $key 键名
     * @param int $ttl 新的过期时间（秒）
     * @return bool
     */
    public function touch(string $key, int $ttl): bool
    {
        $prefixedKey = $this->getKey($key);
        $result = $this->memcached->touch($prefixedKey, $ttl);

        // 同步更新 meta TTL 键
        if ($result && $ttl > 0) {
            $metaKey = $this->getMetaTtlKey($key);
            $this->memcached->set($metaKey, time() + $ttl, $ttl);
        }

        return $result;
    }

    /**
     * 获取键的剩余过期时间（秒）
     *
     * Memcached 无原生 TTL 查询能力，通过额外的 meta 键记录过期时间戳。
     *
     * @param string $key 键名
     * @return int 剩余秒数，-2 表示键不存在，-1 表示永不过期
     */
    public function getRemainingTtl(string $key): int
    {
        // 先检查主键是否存在
        if (!$this->has($key)) {
            return -2;
        }

        // 读取 meta TTL 键
        $metaKey = $this->getMetaTtlKey($key);
        $expiresAt = $this->memcached->get($metaKey);

        // meta 键不存在或读取失败，说明键永不过期
        if ($this->memcached->getResultCode() !== Memcached::RES_SUCCESS) {
            return -1;
        }

        $remaining = (int) $expiresAt - time();

        return $remaining > 0 ? $remaining : -2;
    }

    /**
     * 清空存储
     *
     * @return bool
     */
    public function clear(): bool
    {
        return $this->memcached->flush();
    }

    /**
     * 获取 Memcached 实例
     */
    public function getMemcached(): Memcached
    {
        return $this->memcached;
    }

    /**
     * Memcached 原子化撤销 Token
     *
     * 注意：Memcached 不支持真正的原子化操作，此处为多步组合实现，
     * 高并发场景下可能存在竞态问题。
     *
     * @param string $jti      JWT ID
     * @param string $uid      用户 ID
     * @param string $platform 平台标识
     * @param int    $ttl      黑名单保留时间（秒）
     * @return int 受影响键数量
     */
    public function atomicRevoke(string $jti, string $uid, string $platform, int $ttl = 3600): int
    {
        $count = 0;
        if ($this->blacklist($jti, $ttl)) {
            $count++;
        }
        $ssoKey = "sso:{$uid}:{$platform}";
        if ($this->get($ssoKey) === $jti) {
            if ($this->delete($ssoKey)) {
                $count++;
            }
        }
        $listKey = "user:{$uid}:{$platform}:tokens";
        $list = (array) $this->get($listKey, []);
        if (in_array($jti, $list, true)) {
            $list = array_values(array_filter($list, static fn(string $x): bool => $x !== $jti));
            $this->set($listKey, $list, $ttl);
            $count++;
        }
        if ($this->delete("token:{$jti}")) {
            $count++;
        }
        return $count;
    }

    /**
     * Memcached 记录用户活跃 Token 列表
     *
     * @param string $uid      用户 ID
     * @param string $platform 平台标识
     * @param string $jti      JWT ID
     * @param int    $ttl      列表保留时间（秒）
     * @return bool
     */
    public function trackUserToken(string $uid, string $platform, string $jti, int $ttl = 0): bool
    {
        $key = "user:{$uid}:{$platform}:tokens";
        $list = (array) $this->get($key, []);
        array_unshift($list, $jti);
        $list = array_slice(array_unique($list), 0, 50);
        return $this->set($key, $list, $ttl);
    }

    /**
     * Memcached 设置 SSO 平台 → JTI 映射
     *
     * @param string $uid      用户 ID
     * @param string $platform 平台标识
     * @param string $jti      JWT ID
     * @param int    $ttl      映射保留时间（秒）
     * @return bool
     */
    public function setSsoMapping(string $uid, string $platform, string $jti, int $ttl = 0): bool
    {
        return $this->set("sso:{$uid}:{$platform}", $jti, $ttl);
    }

    /**
     * Memcached 获取 SSO 平台 → JTI 映射
     *
     * @param string $uid      用户 ID
     * @param string $platform 平台标识
     * @return string|null JTI，不存在时返回 null
     */
    public function getSsoMapping(string $uid, string $platform): ?string
    {
        $value = $this->get("sso:{$uid}:{$platform}");
        if ($value === null) {
            return null;
        }
        return (string) $value;
    }
}
