<?php

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\StorageInterface;

class MemoryStorage implements StorageInterface
{
    /**
     * @var array<string, array{value: mixed, expires_at: int}>
     */
    protected array $storage = [];
    /**
     * @var array<string, int>
     */
    protected array $blacklist = [];
    protected int $limit;

    /**
     * 构造函数
     *
     * @param array<string, mixed> $config 配置数组
     */
    public function __construct(array $config = [])
    {
        $this->limit = $config['limit'] ?? 10000;
    }

    /**
     * 设置键值对
     */
    public function set(string $key, mixed $value, int $ttl = 0): bool
    {
        // 如果达到限制，移除最旧的项
        if (count($this->storage) >= $this->limit) {
            array_shift($this->storage);
        }

        $this->storage[$key] = [
            'value' => $value,
            'expires_at' => $ttl > 0 ? time() + $ttl : 0,
        ];

        return true;
    }

    /**
     * 获取键对应的值
     */
    public function get(string $key, mixed $default = null): mixed
    {
        if (!isset($this->storage[$key])) {
            return $default;
        }

        $item = $this->storage[$key];

        // 检查是否过期
        if ($item['expires_at'] > 0 && time() > $item['expires_at']) {
            unset($this->storage[$key]);
            return $default;
        }

        return $item['value'];
    }

    /**
     * 删除键
     */
    public function delete(string $key): bool
    {
        unset($this->storage[$key]);
        return true;
    }

    /**
     * 检查键是否存在
     */
    public function has(string $key): bool
    {
        return isset($this->storage[$key]);
    }

    /**
     * 批量设置键值对
     */
    public function setMultiple(array $values, int $ttl = 0): bool
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value, $ttl);
        }

        return true;
    }

    /**
     * 批量获取键值对
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
     */
    public function deleteMultiple(array $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    /**
     * 将键加入黑名单
     */
    public function blacklist(string $jti, int $ttl = 3600): bool
    {
        $this->blacklist[$jti] = time() + $ttl;
        return true;
    }

    /**
     * 检查键是否在黑名单中
     */
    public function isBlacklisted(string $jti): bool
    {
        if (!isset($this->blacklist[$jti])) {
            return false;
        }

        // 检查是否过期
        if (time() > $this->blacklist[$jti]) {
            unset($this->blacklist[$jti]);
            return false;
        }

        return true;
    }

    /**
     * 清理过期项
     */
    public function cleanExpired(): bool
    {
        $count = 0;
        $now = time();

        // 清理过期的存储项
        foreach ($this->storage as $key => $item) {
            if ($item['expires_at'] > 0 && $now > $item['expires_at']) {
                unset($this->storage[$key]);
                $count++;
            }
        }

        // 清理过期的黑名单项
        foreach ($this->blacklist as $jti => $expiresAt) {
            if ($now > $expiresAt) {
                unset($this->blacklist[$jti]);
                $count++;
            }
        }

        return true;
    }

    /**
     * 获取存储统计信息
     */
    public function getStats(): array
    {
        return [
            'storage_count' => count($this->storage),
            'blacklist_count' => count($this->blacklist),
            'limit' => $this->limit,
        ];
    }
}
