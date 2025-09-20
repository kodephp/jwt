<?php

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\StorageInterface;
use Redis;

class RedisStorage implements StorageInterface
{
    protected Redis $redis;
    protected string $prefix;
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
        
        $this->redis->connect($host, $port, $timeout, null, $retryInterval, $readTimeout);
        
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
            return $this->redis->setex($key, $ttl, $serializedValue);
        }
        
        return $this->redis->set($key, $serializedValue);
    }
    
    /**
     * 获取键对应的值
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
     * 清理过期项（Redis会自动清理过期项）
     */
    public function cleanExpired(): int
    {
        // Redis会自动清理过期项，这里返回0表示没有手动清理
        return 0;
    }
    
    /**
     * 获取Redis实例
     */
    public function getRedis(): Redis
    {
        return $this->redis;
    }
}