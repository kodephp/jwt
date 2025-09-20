<?php

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\StorageInterface;

class FileStorage implements StorageInterface
{
    protected string $path;
    protected string $extension;
    protected array $config;
    
    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->path = rtrim($config['path'] ?? sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        $this->extension = $config['extension'] ?? '.jwt';
        
        // 确保目录存在
        if (!is_dir($this->path)) {
            mkdir($this->path, 0755, true);
        }
    }
    
    /**
     * 获取文件路径
     */
    protected function getFilePath(string $key): string
    {
        // 清理键名，防止路径遍历
        $cleanKey = preg_replace('/[^a-zA-Z0-9._-]/', '_', $key);
        return $this->path . $cleanKey . $this->extension;
    }
    
    /**
     * 设置键值对
     */
    public function set(string $key, mixed $value, int $ttl = 0): bool
    {
        $filePath = $this->getFilePath($key);
        
        // 创建数据数组
        $data = [
            'value' => $value,
            'expires_at' => $ttl > 0 ? time() + $ttl : 0,
            'created_at' => time()
        ];
        
        // 序列化数据
        $serializedData = json_encode($data, JSON_PRETTY_PRINT);
        
        // 写入文件
        $result = file_put_contents($filePath, $serializedData, LOCK_EX);
        
        return $result !== false;
    }
    
    /**
     * 获取键对应的值
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $filePath = $this->getFilePath($key);
        
        // 检查文件是否存在
        if (!file_exists($filePath)) {
            return $default;
        }
        
        // 读取文件内容
        $serializedData = file_get_contents($filePath);
        
        if ($serializedData === false) {
            return $default;
        }
        
        // 反序列化数据
        $data = json_decode($serializedData, true);
        
        if ($data === null) {
            return $default;
        }
        
        // 检查是否过期
        if ($data['expires_at'] > 0 && $data['expires_at'] < time()) {
            // 删除过期文件
            $this->delete($key);
            return $default;
        }
        
        return $data['value'];
    }
    
    /**
     * 删除键
     */
    public function delete(string $key): bool
    {
        $filePath = $this->getFilePath($key);
        
        // 检查文件是否存在
        if (!file_exists($filePath)) {
            return false;
        }
        
        // 删除文件
        return unlink($filePath);
    }
    
    /**
     * 检查键是否存在
     */
    public function has(string $key): bool
    {
        $filePath = $this->getFilePath($key);
        
        // 检查文件是否存在
        if (!file_exists($filePath)) {
            return false;
        }
        
        // 读取文件内容
        $serializedData = file_get_contents($filePath);
        
        if ($serializedData === false) {
            return false;
        }
        
        // 反序列化数据
        $data = json_decode($serializedData, true);
        
        if ($data === null) {
            return false;
        }
        
        // 检查是否过期
        if ($data['expires_at'] > 0 && $data['expires_at'] < time()) {
            // 删除过期文件
            $this->delete($key);
            return false;
        }
        
        return true;
    }
    
    /**
     * 将键加入黑名单
     */
    public function blacklist(string $jti, int $ttl = 3600): bool
    {
        return $this->set("blacklist_{$jti}", 1, $ttl);
    }
    
    /**
     * 检查键是否在黑名单中
     */
    public function isBlacklisted(string $jti): bool
    {
        return $this->has("blacklist_{$jti}");
    }
    
    /**
     * 清理过期项
     */
    public function cleanExpired(): int
    {
        $count = 0;
        
        // 获取目录中的所有文件
        $files = glob($this->path . '*' . $this->extension);
        
        foreach ($files as $file) {
            // 读取文件内容
            $serializedData = file_get_contents($file);
            
            if ($serializedData === false) {
                continue;
            }
            
            // 反序列化数据
            $data = json_decode($serializedData, true);
            
            if ($data === null) {
                continue;
            }
            
            // 检查是否过期
            if ($data['expires_at'] > 0 && $data['expires_at'] < time()) {
                // 删除过期文件
                if (unlink($file)) {
                    $count++;
                }
            }
        }
        
        return $count;
    }
}