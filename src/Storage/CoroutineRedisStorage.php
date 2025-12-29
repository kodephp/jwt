<?php

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\StorageInterface;
use Swoole\Coroutine\Redis as CoRedis;

/**
 * 协程 Redis 存储实现
 *
 * 使用 Swoole 协程 Redis 作为 JWT 存储后端，适用于高性能异步场景
 */
class CoroutineRedisStorage implements StorageInterface
{
    /** @var CoRedis 协程 Redis 实例 */
    protected CoRedis $redis;
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
     * 连接Redis
     */
    protected function connect(): void
    {
        $this->redis = new CoRedis();

        $host = $this->config['host'] ?? '127.0.0.1';
        $port = $this->config['port'] ?? 6379;
        $timeout = $this->config['timeout'] ?? 0;

        $this->redis->connect($host, $port, $timeout);

        // 验证密码
        if (!empty($this->config['password'])) {
            $this->redis->auth($this->config['password']);
        }

        // 选择数据库
        if (isset($this->config['database'])) {
            $this->redis->select($this->config['database']);
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

        // 序列化值
        $serializedValue = json_encode($value);

        if ($ttl > 0) {
            $result = $this->redis->setex($key, $ttl, $serializedValue);
        } else {
            $result = $this->redis->set($key, $serializedValue);
        }

        // 如果连接断开，尝试重新连接
        if ($result === false && $this->redis->errCode === 1) {
            $this->connect();
            if ($ttl > 0) {
                $result = $this->redis->setex($key, $ttl, $serializedValue);
            } else {
                $result = $this->redis->set($key, $serializedValue);
            }
        }

        return (bool) $result;
    }

    /**
     * 获取键对应的值
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $key = $this->getKey($key);
        $value = $this->redis->get($key);

        // 如果连接断开，尝试重新连接
        if ($value === false && $this->redis->errCode === 1) {
            $this->connect();
            $value = $this->redis->get($key);
        }

        if ($value === false) {
            return $default;
        }

        $unserializedValue = json_decode($value, true);

        // 如果JSON解码失败，返回原始值
        return $unserializedValue === null ? $value : $unserializedValue;
    }

    /**
     * 删除键
     */
    public function delete(string $key): bool
    {
        $key = $this->getKey($key);
        $result = $this->redis->del($key);

        // 如果连接断开，尝试重新连接
        if ($result === false && $this->redis->errCode === 1) {
            $this->connect();
            $result = $this->redis->del($key);
        }

        return (bool) $result;
    }

    /**
     * 检查键是否存在
     */
    public function has(string $key): bool
    {
        $key = $this->getKey($key);
        $result = $this->redis->exists($key);

        // 如果连接断开，尝试重新连接
        if ($result === false && $this->redis->errCode === 1) {
            $this->connect();
            $result = $this->redis->exists($key);
        }

        return (bool) $result;
    }

    /**
     * 将键加入黑名单
     */
    public function blacklist(string $jti, int $ttl = 3600): bool
    {
        $key = $this->getKey("blacklist:{$jti}");
        $result = $this->redis->setex($key, $ttl, '1');

        // 如果连接断开，尝试重新连接
        if ($result === false && $this->redis->errCode === 1) {
            $this->connect();
            $result = $this->redis->setex($key, $ttl, '1');
        }

        return (bool) $result;
    }

    /**
     * 检查键是否在黑名单中
     */
    public function isBlacklisted(string $jti): bool
    {
        $key = $this->getKey("blacklist:{$jti}");
        $result = $this->redis->exists($key);

        // 如果连接断开，尝试重新连接
        if ($result === false && $this->redis->errCode === 1) {
            $this->connect();
            $result = $this->redis->exists($key);
        }

        return (bool) $result;
    }

    /**
     * 清理过期项（Redis会自动清理过期项）
     *
     * @return bool
     */
    public function cleanExpired(): bool
    {
        return true;
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
     * 获取存储统计信息
     *
     * @return array<string, mixed>
     */
    public function getStats(): array
    {
        return [
            'type' => 'coroutine_redis',
            'prefix' => $this->prefix,
            'connected' => true,
        ];
    }

    /**
     * 获取Redis实例
     */
    public function getRedis(): CoRedis
    {
        return $this->redis;
    }
}
