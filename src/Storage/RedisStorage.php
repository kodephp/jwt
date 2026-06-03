<?php

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\StorageInterface;
use Redis;

/**
 * Redis 存储实现
 *
 * 使用 Redis 作为 JWT 存储后端，支持高性能和高可用性场景。
 *
 * 安全增强（v1.8.0+）：
 * - 使用 Lua 脚本实现"黑名单 + 用户 Token 集合 + SSO 标记"原子化撤销。
 * - 引入连接健康检查与惰性重连，提升高可用场景下的稳定性。
 * - 引入批量管道操作与统计能力，便于监控与告警。
 */
class RedisStorage implements StorageInterface
{
    /**
     * Lua：原子化"加入黑名单并清理 SSO 映射"
     *
     * KEYS[1]  blacklist:{jti}
     * KEYS[2]  sso:{uid}:{platform}
     * KEYS[3]  user:{uid}:{platform}:tokens
     * KEYS[4]  token:{jti}
     *
     * ARGV[1]  ttl（秒）
     * ARGV[2]  current sso jti（用于比对）
     *
     * 返回：受影响键数量
     */
    private const LUA_ATOMIC_REVOKE = <<<'LUA'
        local count = 0
        redis.call('SET', KEYS[1], '1', 'EX', tonumber(ARGV[1]))
        count = count + 1
        local existing = redis.call('GET', KEYS[2])
        if existing == ARGV[2] then
            redis.call('DEL', KEYS[2])
            count = count + 1
        end
        redis.call('LREM', KEYS[3], 0, ARGV[2])
        redis.call('DEL', KEYS[4])
        count = count + 1
        return count
    LUA;

    /** @var Redis Redis 实例 */
    protected Redis $redis;
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
        $this->redis = new Redis();

        $host = $this->config['host'] ?? '127.0.0.1';
        $port = $this->config['port'] ?? 6379;
        $timeout = $this->config['timeout'] ?? 0;
        $retryInterval = $this->config['retry_interval'] ?? 0;
        $readTimeout = $this->config['read_timeout'] ?? 0;
        $persistent = (bool) ($this->config['persistent'] ?? false);
        $persistentId = (string) ($this->config['persistent_id'] ?? 'kode_jwt_redis');

        if ($persistent) {
            $this->redis->pconnect($host, $port, $timeout, $persistentId, $retryInterval, $readTimeout);
        } else {
            $this->redis->connect($host, $port, $timeout, null, $retryInterval, $readTimeout);
        }

        // 验证密码
        if (!empty($this->config['password'])) {
            $this->redis->auth($this->config['password']);
        }

        // 选择数据库
        if (isset($this->config['database'])) {
            $this->redis->select($this->config['database']);
        }

        // 设置读写超时（毫秒）以提升响应可控性
        if (isset($this->config['read_write_timeout'])) {
            $this->redis->setOption(Redis::OPT_READ_TIMEOUT, (string) $this->config['read_write_timeout']);
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
            return $this->redis->setex($key, $ttl, $serializedValue);
        }

        return $this->redis->set($key, $serializedValue);
    }

    /**
     * 获取键对应的值
     *
     * @param string $key 键名
     * @param mixed $default 默认值
     * @return mixed
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $key = $this->getKey($key);
        $value = $this->redis->get($key);

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
        return (bool) $this->redis->del($key);
    }

    /**
     * 检查键是否存在
     */
    public function has(string $key): bool
    {
        $key = $this->getKey($key);
        return (bool) $this->redis->exists($key);
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
        $pipe = $this->redis->multi();

        foreach ($values as $key => $value) {
            $redisKey = $this->getKey($key);
            $serializedValue = json_encode($value);

            if ($ttl > 0) {
                $pipe->setex($redisKey, $ttl, $serializedValue);
            } else {
                $pipe->set($redisKey, $serializedValue);
            }
        }

        $results = $pipe->exec();

        // 检查所有操作是否成功
        foreach ($results as $result) {
            if ($result === false) {
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
        $redisKeys = array_map([$this, 'getKey'], $keys);
        $values = $this->redis->mget($redisKeys);

        $results = [];
        foreach ($keys as $i => $key) {
            $value = $values[$i];

            if ($value === false) {
                $results[$key] = $default;
            } else {
                $unserializedValue = json_decode($value, true);
                $results[$key] = $unserializedValue === null ? $value : $unserializedValue;
            }
        }

        return $results;
    }

    /**
     * 批量删除键
     */
    public function deleteMultiple(array $keys): bool
    {
        $redisKeys = array_map([$this, 'getKey'], $keys);
        return (bool) $this->redis->del($redisKeys);
    }

    /**
     * 将键加入黑名单
     */
    public function blacklist(string $jti, int $ttl = 3600): bool
    {
        $key = $this->getKey("blacklist:{$jti}");
        return (bool) $this->redis->setex($key, $ttl, '1');
    }

    /**
     * 检查键是否在黑名单中
     */
    public function isBlacklisted(string $jti): bool
    {
        $key = $this->getKey("blacklist:{$jti}");
        return (bool) $this->redis->exists($key);
    }

    /**
     * 原子化撤销 Token
     *
     * 一次性完成以下操作，避免在多个步骤之间出现"半撤销"状态：
     *   1. 将 JTI 加入黑名单
     *   2. 如果传入的 SSO 标记匹配则清理 SSO 标记
     *   3. 从用户 Token 列表中移除 JTI
     *   4. 清理 token 详情键
     *
     * 推荐在 SSO 场景下使用，确保多步操作的强一致性。
     *
     * @param string $jti       JWT ID
     * @param string $uid       用户 ID
     * @param string $platform  平台标识
     * @param int    $ttl       黑名单保留时间（秒）
     * @return int 受影响键数量
     */
    public function atomicRevoke(string $jti, string $uid, string $platform, int $ttl = 3600): int
    {
        $keys = [
            $this->getKey("blacklist:{$jti}"),
            $this->getKey("sso:{$uid}:{$platform}"),
            $this->getKey("user:{$uid}:{$platform}:tokens"),
            $this->getKey("token:{$jti}"),
        ];

        $result = $this->redis->eval(self::LUA_ATOMIC_REVOKE, [...$keys, (string) max(1, $ttl), $jti], count($keys));

        return (int) $result;
    }

    /**
     * 将 JTI 添加到用户的活跃 Token 集合
     *
     * @param string $uid       用户 ID
     * @param string $platform  平台标识
     * @param string $jti       JWT ID
     * @param int    $ttl       列表保留时间（秒）
     * @return bool
     */
    public function trackUserToken(string $uid, string $platform, string $jti, int $ttl = 0): bool
    {
        $key = $this->getKey("user:{$uid}:{$platform}:tokens");
        $this->redis->lPush($key, $jti);
        // 仅保留最近的 50 条以避免列表无限增长
        $this->redis->lTrim($key, 0, 49);
        if ($ttl > 0) {
            $this->redis->expire($key, $ttl);
        }
        return true;
    }

    /**
     * 设置 SSO 平台 → JTI 映射
     *
     * @param string $uid       用户 ID
     * @param string $platform  平台标识
     * @param string $jti       JWT ID
     * @param int    $ttl       过期时间（秒）
     * @return bool
     */
    public function setSsoMapping(string $uid, string $platform, string $jti, int $ttl = 0): bool
    {
        $key = $this->getKey("sso:{$uid}:{$platform}");
        if ($ttl > 0) {
            return (bool) $this->redis->setex($key, $ttl, $jti);
        }
        return (bool) $this->redis->set($key, $jti);
    }

    /**
     * 获取 SSO 平台 → JTI 映射
     */
    public function getSsoMapping(string $uid, string $platform): ?string
    {
        $key = $this->getKey("sso:{$uid}:{$platform}");
        $value = $this->redis->get($key);
        if ($value === false || $value === null) {
            return null;
        }
        return (string) $value;
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
     * 获取存储统计信息
     *
     * @return array<string, mixed>
     */
    public function getStats(): array
    {
        return [
            'type' => 'redis',
            'prefix' => $this->prefix,
            'connected' => true,
        ];
    }

    public function touch(string $key, int $ttl): bool
    {
        $key = $this->getKey($key);
        return (bool) $this->redis->expire($key, $ttl);
    }

    public function getRemainingTtl(string $key): int
    {
        $key = $this->getKey($key);
        $ttl = $this->redis->ttl($key);
        return $ttl >= 0 ? $ttl : -2;
    }

    public function clear(): bool
    {
        $keys = $this->redis->keys($this->prefix . '*');
        if (empty($keys)) {
            return true;
        }
        return (bool) $this->redis->del($keys);
    }

    /**
     * 获取Redis实例
     */
    public function getRedis(): Redis
    {
        return $this->redis;
    }
}
