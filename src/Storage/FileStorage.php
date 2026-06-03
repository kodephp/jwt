<?php

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\SsoStorageInterface;
use Kode\Jwt\Contract\StorageInterface;

/**
 * 文件存储实现
 *
 * 使用文件系统作为 JWT 存储后端，适用于简单的单机部署场景
 */
class FileStorage implements SsoStorageInterface
{
    /** @var string 存储目录路径 */
    protected string $path;
    /** @var string 文件扩展名 */
    protected string $extension;
    /** @var array<string, mixed> 配置数组 */
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
     *
     * @return bool
     */
    public function cleanExpired(): bool
    {
        $count = $this->cleanExpiredItems();
        return $count >= 0;
    }

    /**
     * 清理过期项（内部方法）
     */
    private function cleanExpiredItems(): int
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
        $files = glob($this->path . '*' . $this->extension);
        return [
            'type' => 'file',
            'path' => $this->path,
            'extension' => $this->extension,
            'file_count' => count($files),
        ];
    }

    public function touch(string $key, int $ttl): bool
    {
        $filePath = $this->getFilePath($key);

        if (!file_exists($filePath)) {
            return false;
        }

        $serializedData = file_get_contents($filePath);

        if ($serializedData === false) {
            return false;
        }

        $data = json_decode($serializedData, true);

        if ($data === null) {
            return false;
        }

        if ($data['expires_at'] > 0 && $data['expires_at'] < time()) {
            $this->delete($key);
            return false;
        }

        $data['expires_at'] = time() + $ttl;
        $result = file_put_contents($filePath, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);

        return $result !== false;
    }

    public function getRemainingTtl(string $key): int
    {
        $filePath = $this->getFilePath($key);

        if (!file_exists($filePath)) {
            return -2;
        }

        $serializedData = file_get_contents($filePath);

        if ($serializedData === false) {
            return -2;
        }

        $data = json_decode($serializedData, true);

        if ($data === null) {
            return -2;
        }

        if ($data['expires_at'] <= 0) {
            return -1;
        }

        $remaining = $data['expires_at'] - time();
        return $remaining > 0 ? $remaining : -2;
    }

    public function clear(): bool
    {
        $files = glob($this->path . '*' . $this->extension);
        $success = true;

        foreach ($files as $file) {
            if (!unlink($file)) {
                $success = false;
            }
        }

        return $success;
    }

    /**
     * 文件存储原子化撤销（无并发安全保证，慎用于高并发场景）
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
     * 文件存储记录用户活跃 Token 列表
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
     * 文件存储设置 SSO 映射
     */
    public function setSsoMapping(string $uid, string $platform, string $jti, int $ttl = 0): bool
    {
        return $this->set("sso:{$uid}:{$platform}", $jti, $ttl);
    }

    /**
     * 文件存储获取 SSO 映射
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
