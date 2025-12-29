<?php

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\StorageInterface;
use Memcached;

/**
 * Memcached 存储实现
 *
 * 使用 Memcached 作为 JWT 存储后端，适用于分布式缓存场景
 */
class MemcachedStorage implements StorageInterface
{
    /** @var Memcached Memcached 实例 */
    protected Memcached $memcached;
    /** @var string 键前缀 */
    protected string $prefix;
    /** @var array<string, mixed> 配置数组 */
    protected array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->prefix = $config['prefix'] ?? 'kode:jwt:';

        $this->connect();
    }

    /**
     * 连接Memcached
     */
    protected function connect(): void
    {
        $this->memcached = new Memcached();

        // 添加服务器
        $servers = $this->config['servers'] ?? [['127.0.0.1', 11211, 100]];
        $this->memcached->addServers($servers);

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
     * 设置键值对
     */
    public function set(string $key, mixed $value, int $ttl = 0): bool
    {
        $key = $this->getKey($key);
        return $this->memcached->set($key, $value, $ttl);
    }

    /**
     * 获取键对应的值
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $key = $this->getKey($key);
        $value = $this->memcached->get($key);

        // 检查是否找到键
        if ($this->memcached->getResultCode() === Memcached::RES_NOTFOUND) {
            return $default;
        }

        return $value;
    }

    /**
     * 删除键
     */
    public function delete(string $key): bool
    {
        $key = $this->getKey($key);
        return $this->memcached->delete($key);
    }

    /**
     * 检查键是否存在
     */
    public function has(string $key): bool
    {
        $key = $this->getKey($key);
        $this->memcached->get($key);

        return $this->memcached->getResultCode() !== Memcached::RES_NOTFOUND;
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

        return $this->memcached->getResultCode() !== Memcached::RES_NOTFOUND;
    }

    /**
     * 清理过期项（Memcached会自动清理过期项）
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
     * 获取Memcached实例
     */
    public function getMemcached(): Memcached
    {
        return $this->memcached;
    }
}
