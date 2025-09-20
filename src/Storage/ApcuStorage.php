<?php

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\StorageInterface;

class ApcuStorage implements StorageInterface
{
    protected string $prefix;
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
     */
    public function cleanExpired(): int
    {
        // APCu会自动清理过期项，这里返回0表示没有手动清理
        return 0;
    }
    
    /**
     * 获取APCu缓存信息
     */
    public function getInfo(): array
    {
        return apcu_cache_info();
    }
}