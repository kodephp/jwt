<?php

declare(strict_types=1);

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\ReplayProtectionInterface;
use Kode\Jwt\Contract\StorageInterface;
use Redis;

/**
 * Redis 防重放保护器
 *
 * 通过 Redis SETNX + 时间窗口实现 JTI+Nonce 组合的防重放校验：
 * 1. 原子性首次消费：SET key value NX PX ttl 确保同一 Nonce 仅被记录一次。
 * 2. 滑动窗口：可选支持，记录最近 N 秒的访问轨迹，识别异常短时间高频重放。
 * 3. 自动过期：依赖 Redis 的键过期机制，无需手动 GC。
 *
 * 典型键设计：
 *   {prefix}replay:jti:{jti}      -> 最近一次 Nonce
 *   {prefix}replay:nonce:{jti}:{nonce} -> 一次性消费标记
 */
class RedisReplayProtection implements ReplayProtectionInterface
{
    /**
     * Lua：原子写入 Nonce 标记
     *
     * KEYS[1] 一次性 Nonce 键
     * ARGV[1] 当前 Unix 时间戳（秒）
     * ARGV[2] 过期时间（毫秒）
     *
     * 返回：
     *   1 = 首次写入（通过）
     *   0 = 已存在（重放，拒绝）
     */
    private const LUA_STORE_NONCE = <<<'LUA'
        if redis.call('EXISTS', KEYS[1]) == 1 then
            return 0
        end
        redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
        return 1
    LUA;

    /**
     * Lua：滑动窗口频率限制
     *
     * KEYS[1] 滑动窗口 ZSet 键
     * ARGV[1] 当前时间戳（毫秒）
     * ARGV[2] 窗口大小（毫秒）
     * ARGV[3] 当前请求 Nonce（用作 member）
     * ARGV[4] ZSet 中允许的最大条数
     *
     * 返回：
     *   1 = 通过
     *   0 = 触发频率限制
     */
    private const LUA_SLIDING_WINDOW = <<<'LUA'
        local now = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local cutoff = now - window
        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
        local count = tonumber(redis.call('ZCARD', KEYS[1]))
        if count >= tonumber(ARGV[4]) then
            return 0
        end
        redis.call('ZADD', KEYS[1], now, ARGV[3])
        redis.call('PEXPIRE', KEYS[1], window)
        return 1
    LUA;

    private Redis $redis;
    private string $prefix;
    private int $defaultTtl;
    private int $slidingWindow;
    private int $slidingMaxRequests;

    /**
     * 构造函数
     *
     * @param StorageInterface|Redis|array<string, mixed> $connection Redis 实例、存储实例或配置
     * @param array<string, mixed> $config 防重放保护器配置
     */
    public function __construct(StorageInterface|Redis|array $connection, array $config = [])
    {
        if ($connection instanceof StorageInterface) {
            // 兼容模式：从存储层取出底层 Redis 实例
            if (method_exists($connection, 'getRedis')) {
                $this->redis = $connection->getRedis();
            } else {
                throw new \InvalidArgumentException('当前存储驱动不支持原生 Redis 实例访问，无法启用防重放保护');
            }
        } elseif ($connection instanceof Redis) {
            $this->redis = $connection;
        } else {
            throw new \InvalidArgumentException('RedisReplayProtection 构造函数参数错误');
        }

        $this->prefix = $config['prefix'] ?? 'kode:jwt:';
        $this->defaultTtl = (int) ($config['ttl'] ?? 3600);
        $this->slidingWindow = (int) ($config['sliding_window'] ?? 0);
        $this->slidingMaxRequests = (int) ($config['sliding_max_requests'] ?? 0);
    }

    /**
     * {@inheritDoc}
     */
    public function checkAndStore(string $jti, string $nonce, int $ttl = 0, int $window = 0): bool
    {
        if ($jti === '' || $nonce === '') {
            // 缺少必要信息时按"放行"处理（由上层决定是否需要）
            return true;
        }

        $ttl = $ttl > 0 ? $ttl : $this->defaultTtl;
        $ttlMs = $ttl * 1000;

        // 1. 一次性 Nonce 消费
        $nonceKey = $this->prefix . "replay:nonce:{$jti}:{$nonce}";
        $result = $this->redis->eval(self::LUA_STORE_NONCE, [$nonceKey, (string) time() * 1000, (string) $ttlMs], 1);
        if ((int) $result !== 1) {
            return false;
        }

        // 2. 滑动窗口校验（可选）
        $windowSeconds = $window > 0 ? $window : $this->slidingWindow;
        if ($windowSeconds > 0 && $this->slidingMaxRequests > 0) {
            $windowKey = $this->prefix . "replay:window:{$jti}";
            $windowMs = $windowSeconds * 1000;
            $nowMs = (string) (int) (microtime(true) * 1000);
            $maxReq = (string) $this->slidingMaxRequests;
            $result = $this->redis->eval(
                self::LUA_SLIDING_WINDOW,
                [$windowKey, $nowMs, (string) $windowMs, $nonce, $maxReq],
                1
            );
            if ((int) $result !== 1) {
                // 触发频率限制：回滚 Nonce 标记，避免下次可用
                $this->redis->del($nonceKey);
                return false;
            }
        }

        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function exists(string $jti, string $nonce): bool
    {
        if ($jti === '' || $nonce === '') {
            return false;
        }

        $key = $this->prefix . "replay:nonce:{$jti}:{$nonce}";
        return (bool) $this->redis->exists($key);
    }

    /**
     * {@inheritDoc}
     */
    public function purge(): int
    {
        $pattern = "{$this->prefix}replay:*";
        $keys = $this->redis->keys($pattern);
        if (empty($keys)) {
            return 0;
        }

        return (int) $this->redis->del($keys);
    }
}
