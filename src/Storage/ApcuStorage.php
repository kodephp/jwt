<?php

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\StorageInterface;

/**
 * APCu 存储实现
 *
 * 使用 APCu 作为 JWT 存储后端，适用于单机 PHP-FPM 场景
 */
class ApcuStorage implements StorageInterface
{
    /** @var string 键前缀 */
    protected string $prefix;
    /** @var array<string, mixed> 配置数组 */
    protected array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->prefix = $config['prefix'] ?? 'kode:jwt:';

        // 检查APCu扩展是否可用
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
     */
    public function set(string $key, mixed $value, int $ttl = 0): bool
    {
        $key = $this->getKey($key);
        return apcu_store($key, $value, $ttl);
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
     */
    public function delete(string $key): bool
    {
        $key = $this->getKey($key);
        return apcu_delete($key);
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
     * 清理过期项（APCu会自动清理过期项）
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
        $info = apcu_cache_info();
        return [
            'type' => 'apcu',
            'prefix' => $this->prefix,
            'memory_size' => $info['mem_size'] ?? 0,
            'num_entries' => $info['num_entries'] ?? 0,
        ];
    }

    /**
     * 获取APCu缓存信息
     */
    public function getInfo(): array
    {
        return apcu_cache_info();
    }
}
