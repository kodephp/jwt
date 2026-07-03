<?php

declare(strict_types=1);

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\SsoStorageInterface;
use Kode\Jwt\Contract\StorageInterface;

/**
 * APCu 存储实现
 *
 * 使用 APCu 作为 JWT 存储后端，适用于单机 PHP-FPM 场景
 */
class ApcuStorage implements SsoStorageInterface
{
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

        // 检查 APCu 扩展是否可用
        if (!extension_loaded('apcu')) {
            throw new \RuntimeException('APCu extension is not loaded');
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
     *
     * 同时额外存储一个 TTL 时间戳键 {$key}:meta_ttl，用于 getRemainingTtl 查询。
     * 主键写入失败时不再写 meta 键，避免状态不一致。
     */
    public function set(string $key, mixed $value, int $ttl = 0): bool
    {
        $prefixedKey = $this->getKey($key);
        $result = apcu_store($prefixedKey, $value, $ttl);

        // 仅在主键写入成功时同步写 meta 键，避免主键失败但仍残留 meta 造成状态不一致
        if ($result && $ttl > 0) {
            $metaKey = $this->getKey("{$key}:meta_ttl");
            // 若 meta 键已存在则覆盖
            apcu_store($metaKey, time() + $ttl, $ttl);
        }

        return $result;
    }

    /**
     * 获取键对应的值
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $key = $this->getKey($key);
        $value = apcu_fetch($key, $success);

        return $success ? $value : $default;
    }

    /**
     * 删除键
     *
     * 同时清理对应的 meta_ttl 键，避免 meta 残留导致 getRemainingTtl 误判。
     */
    public function delete(string $key): bool
    {
        $prefixedKey = $this->getKey($key);
        $metaKey = $this->getKey("{$key}:meta_ttl");

        // 主键不存在时 apcu_delete 返回 false，这里宽容处理：只要任一键被成功删除即视为成功
        $mainDeleted = apcu_delete($prefixedKey);
        apcu_delete($metaKey);

        return $mainDeleted;
    }

    /**
     * 检查键是否存在
     */
    public function has(string $key): bool
    {
        $key = $this->getKey($key);
        return apcu_exists($key);
    }

    /**
     * 将键加入黑名单
     */
    public function blacklist(string $jti, int $ttl = 3600): bool
    {
        $key = $this->getKey("blacklist:{$jti}");
        return apcu_store($key, true, $ttl);
    }

    /**
     * 检查键是否在黑名单中
     */
    public function isBlacklisted(string $jti): bool
    {
        $key = $this->getKey("blacklist:{$jti}");
        return apcu_exists($key);
    }

    /**
     * 清理过期项（APCu 会自动清理过期项）
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
     * 延长键的过期时间
     *
     * APCu 不支持直接修改 TTL，需要先 fetch 再 store。
     */
    public function touch(string $key, int $ttl): bool
    {
        $prefixedKey = $this->getKey($key);
        $value = apcu_fetch($prefixedKey, $success);

        if (!$success) {
            return false;
        }

        $result = apcu_store($prefixedKey, $value, $ttl);

        // 同步更新 TTL 时间戳键
        if ($ttl > 0) {
            $metaKey = $this->getKey("{$key}:meta_ttl");
            apcu_store($metaKey, time() + $ttl, $ttl);
        }

        return $result;
    }

    /**
     * 获取键的剩余过期时间（秒）
     *
     * APCu 无原生 TTL 查询，通过辅助键 {$key}:meta_ttl 记录的过期时间戳计算。
     *
     * @return int 剩余秒数，-2 表示键不存在，-1 表示永不过期
     */
    public function getRemainingTtl(string $key): int
    {
        $prefixedKey = $this->getKey($key);

        if (!apcu_exists($prefixedKey)) {
            return -2;
        }

        $metaKey = $this->getKey("{$key}:meta_ttl");
        $expiresAt = apcu_fetch($metaKey, $success);

        // 没有记录过期时间戳，视为永不过期
        if (!$success || !is_int($expiresAt) || $expiresAt <= 0) {
            return -1;
        }

        $remaining = $expiresAt - time();
        return $remaining > 0 ? $remaining : -2;
    }

    /**
     * 清空存储
     */
    public function clear(): bool
    {
        return apcu_clear_cache();
    }

    /**
     * 获取存储统计信息
     *
     * @return array<string, mixed>
     */
    public function getStats(): array
    {
        $info = apcu_cache_info();

        return [
            'type' => 'apcu',
            'prefix' => $this->prefix,
            'memory_size' => $info['mem_size'] ?? 0,
            'num_entries' => $info['num_entries'] ?? 0,
        ];
    }

    /**
     * 获取 APCu 缓存信息
     *
     * @return array<string, mixed>
     */
    public function getInfo(): array
    {
        return apcu_cache_info();
    }

    /**
     * 原子化撤销 Token
     *
     * APCu 共享内存环境下不保证原子性，按顺序执行各步骤：
     * 黑名单 → SSO 清理 → 用户列表清理 → Token 详情清理。
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
     * 记录到用户活跃 Token 列表
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
     * 设置 SSO 平台 → JTI 映射
     */
    public function setSsoMapping(string $uid, string $platform, string $jti, int $ttl = 0): bool
    {
        return $this->set("sso:{$uid}:{$platform}", $jti, $ttl);
    }

    /**
     * 获取 SSO 平台 → JTI 映射
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
