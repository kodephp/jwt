<?php

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\StorageInterface;
use PDO;

/**
 * 数据库存储实现
 *
 * 使用数据库作为 JWT 存储后端，适用于需要持久化存储的场景
 */
class DatabaseStorage implements StorageInterface
{
    /** @var PDO 数据库连接实例 */
    protected PDO $pdo;
    /** @var string 表名 */
    protected string $table;
    /** @var array<string, mixed> 配置数组 */
    protected array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->table = $config['table'] ?? 'jwt_tokens';

        $this->connect();
    }

    /**
     * 连接数据库
     */
    protected function connect(): void
    {
        $dsn = $this->config['dsn'] ?? '';
        $username = $this->config['username'] ?? '';
        $password = $this->config['password'] ?? '';
        $options = $this->config['options'] ?? [];

        $this->pdo = new PDO($dsn, $username, $password, $options);
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // 创建表（如果不存在）
        $this->createTable();
    }

    /**
     * 创建表
     */
    protected function createTable(): void
    {
        $sql = "CREATE TABLE IF NOT EXISTS {$this->table} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_key VARCHAR(255) NOT NULL UNIQUE,
            token_value TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        )";

        $this->pdo->exec($sql);

        // 创建黑名单表（如果不存在）
        $blacklistTable = $this->table . '_blacklist';
        $sql = "CREATE TABLE IF NOT EXISTS {$blacklistTable} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jti VARCHAR(255) NOT NULL UNIQUE,
            revoked_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            expires_at INTEGER NOT NULL
        )";

        $this->pdo->exec($sql);
    }

    /**
     * 设置键值对
     */
    public function set(string $key, mixed $value, int $ttl = 0): bool
    {
        // 序列化值
        $serializedValue = json_encode($value);

        // 计算过期时间
        $expiresAt = $ttl > 0 ? time() + $ttl : 0;

        $sql = "INSERT OR REPLACE INTO {$this->table} (token_key, token_value, expires_at) VALUES (?, ?, ?)";
        $stmt = $this->pdo->prepare($sql);

        return $stmt->execute([$key, $serializedValue, $expiresAt]);
    }

    /**
     * 获取键对应的值
     */
    public function get(string $key, mixed $default = null): mixed
    {
        // 先清理过期项
        $this->cleanExpired();

        $sql = "SELECT token_value, expires_at FROM {$this->table} WHERE token_key = ?";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$key]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result === false) {
            return $default;
        }

        // 检查是否过期
        if ($result['expires_at'] > 0 && $result['expires_at'] < time()) {
            // 删除过期项
            $this->delete($key);
            return $default;
        }

        $unserializedValue = json_decode($result['token_value'], true);

        // 如果JSON解码失败，返回原始值
        return $unserializedValue === null ? $result['token_value'] : $unserializedValue;
    }

    /**
     * 删除键
     */
    public function delete(string $key): bool
    {
        $sql = "DELETE FROM {$this->table} WHERE token_key = ?";
        $stmt = $this->pdo->prepare($sql);

        return $stmt->execute([$key]);
    }

    /**
     * 检查键是否存在
     */
    public function has(string $key): bool
    {
        // 先清理过期项
        $this->cleanExpired();

        $sql = "SELECT COUNT(*) FROM {$this->table} WHERE token_key = ?";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$key]);
        $count = $stmt->fetchColumn();

        return $count > 0;
    }

    /**
     * 将键加入黑名单
     */
    public function blacklist(string $jti, int $ttl = 3600): bool
    {
        $blacklistTable = $this->table . '_blacklist';
        $revokedAt = time();
        $expiresAt = $revokedAt + $ttl;

        $sql = "INSERT OR REPLACE INTO {$blacklistTable} (jti, revoked_at, expires_at) VALUES (?, ?, ?)";
        $stmt = $this->pdo->prepare($sql);

        return $stmt->execute([$jti, $revokedAt, $expiresAt]);
    }

    /**
     * 检查键是否在黑名单中
     */
    public function isBlacklisted(string $jti): bool
    {
        // 先清理过期项
        $this->cleanExpired();

        $blacklistTable = $this->table . '_blacklist';
        $sql = "SELECT COUNT(*) FROM {$blacklistTable} WHERE jti = ?";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$jti]);
        $count = $stmt->fetchColumn();

        return $count > 0;
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
        // 清理过期的普通项
        $sql = "DELETE FROM {$this->table} WHERE expires_at > 0 AND expires_at < ?";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([time()]);
        $count = $stmt->rowCount();

        // 清理过期的黑名单项
        $blacklistTable = $this->table . '_blacklist';
        $sql = "DELETE FROM {$blacklistTable} WHERE expires_at < ?";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([time()]);
        $count += $stmt->rowCount();

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
        $sql = "SELECT COUNT(*) as count FROM {$this->table}";
        $stmt = $this->pdo->query($sql);
        $tokenCount = $stmt->fetchColumn();

        $blacklistTable = $this->table . '_blacklist';
        $sql = "SELECT COUNT(*) as count FROM {$blacklistTable}";
        $stmt = $this->pdo->query($sql);
        $blacklistCount = $stmt->fetchColumn();

        return [
            'type' => 'database',
            'table' => $this->table,
            'token_count' => $tokenCount,
            'blacklist_count' => $blacklistCount,
        ];
    }

    /**
     * 获取PDO实例
     */
    public function getPdo(): PDO
    {
        return $this->pdo;
    }
}
