<?php

declare(strict_types=1);

namespace Kode\Jwt\Storage;

use InvalidArgumentException;
use Kode\Jwt\Contract\SsoStorageInterface;
use Kode\Jwt\Contract\StorageInterface;
use PDO;

/**
 * 数据库存储实现
 *
 * 使用数据库作为 JWT 存储后端，适用于需要持久化存储的场景。
 * 支持 SQLite 和 MySQL 两种数据库方言，通过 DSN 自动检测。
 */
class DatabaseStorage implements SsoStorageInterface
{
    /** @var PDO 数据库连接实例 */
    protected PDO $pdo;
    /** @var string 表名 */
    protected string $table;
    /** @var array<string, mixed> 配置数组 */
    protected array $config;
    /** @var string 数据库驱动类型（sqlite 或 mysql） */
    protected string $driver;

    /**
     * 构造函数
     *
     * @param array<string, mixed> $config 配置数组
     */
    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->table = $config['table'] ?? 'jwt_tokens';

        // 校验表名，防止 SQL 注入
        if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $this->table)) {
            throw new InvalidArgumentException(sprintf('非法表名: %s', $this->table));
        }

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
        // 关闭预处理模拟，强制使用真正的预处理语句，提升安全性
        $this->pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);

        // 检测数据库驱动类型
        $this->driver = $this->detectDriver($dsn);

        // 创建表（如果不存在）
        $this->createTable();
    }

    /**
     * 检测数据库驱动类型
     *
     * 优先通过 PDO::ATTR_DRIVER_NAME 获取，失败时回退到 DSN 前缀解析。
     *
     * @param string $dsn 数据源名称
     * @return string 驱动类型（sqlite 或 mysql）
     */
    protected function detectDriver(string $dsn): string
    {
        $driverName = (string) $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        if ($driverName !== '') {
            return strtolower($driverName);
        }

        // 回退到 DSN 前缀解析
        $lowerDsn = strtolower($dsn);
        if (str_starts_with($lowerDsn, 'sqlite')) {
            return 'sqlite';
        }

        return 'mysql';
    }

    /**
     * 创建表
     */
    protected function createTable(): void
    {
        // 根据驱动类型选择对应的 SQL 方言
        if ($this->driver === 'sqlite') {
            $primaryKey = 'INTEGER PRIMARY KEY AUTOINCREMENT';
            $timestampDefault = "(strftime('%s', 'now'))";
        } else {
            $primaryKey = 'INT AUTO_INCREMENT PRIMARY KEY';
            $timestampDefault = 'UNIX_TIMESTAMP()';
        }

        $sql = "CREATE TABLE IF NOT EXISTS {$this->table} (
            id {$primaryKey},
            token_key VARCHAR(255) NOT NULL UNIQUE,
            token_value TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL DEFAULT {$timestampDefault}
        )";

        $this->pdo->exec($sql);

        // 创建黑名单表（如果不存在）
        $blacklistTable = $this->table . '_blacklist';
        $sql = "CREATE TABLE IF NOT EXISTS {$blacklistTable} (
            id {$primaryKey},
            jti VARCHAR(255) NOT NULL UNIQUE,
            revoked_at INTEGER NOT NULL DEFAULT {$timestampDefault},
            expires_at INTEGER NOT NULL
        )";

        $this->pdo->exec($sql);
    }

    /**
     * 设置键值对
     *
     * @param string $key 键名
     * @param mixed $value 值
     * @param int $ttl 过期时间（秒），0 表示永不过期
     * @return bool
     */
    public function set(string $key, mixed $value, int $ttl = 0): bool
    {
        // 序列化值
        $serializedValue = json_encode($value);

        // 计算过期时间
        $expiresAt = $ttl > 0 ? time() + $ttl : 0;

        if ($this->driver === 'sqlite') {
            $sql = "INSERT OR REPLACE INTO {$this->table} (token_key, token_value, expires_at) VALUES (?, ?, ?)";
            $stmt = $this->pdo->prepare($sql);

            return $stmt->execute([$key, $serializedValue, $expiresAt]);
        }

        // MySQL: INSERT ... ON DUPLICATE KEY UPDATE
        $sql = "INSERT INTO {$this->table} (token_key, token_value, expires_at) VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE token_value = VALUES(token_value), expires_at = VALUES(expires_at)";
        $stmt = $this->pdo->prepare($sql);

        return $stmt->execute([$key, $serializedValue, $expiresAt]);
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
        // 概率触发过期清理，避免每次读都全表扫描
        $this->maybeCleanExpired();

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
     *
     * @param string $key 键名
     * @return bool
     */
    public function delete(string $key): bool
    {
        $sql = "DELETE FROM {$this->table} WHERE token_key = ?";
        $stmt = $this->pdo->prepare($sql);

        return $stmt->execute([$key]);
    }

    /**
     * 检查键是否存在
     *
     * @param string $key 键名
     * @return bool
     */
    public function has(string $key): bool
    {
        // 概率触发过期清理，避免每次读都全表扫描
        $this->maybeCleanExpired();

        $sql = "SELECT COUNT(*) FROM {$this->table} WHERE token_key = ?";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$key]);
        $count = $stmt->fetchColumn();

        return $count > 0;
    }

    /**
     * 将键加入黑名单
     *
     * @param string $jti JWT ID
     * @param int $ttl 黑名单保留时间（秒）
     * @return bool
     */
    public function blacklist(string $jti, int $ttl = 3600): bool
    {
        $blacklistTable = $this->table . '_blacklist';
        $revokedAt = time();
        $expiresAt = $revokedAt + $ttl;

        if ($this->driver === 'sqlite') {
            $sql = "INSERT OR REPLACE INTO {$blacklistTable} (jti, revoked_at, expires_at) VALUES (?, ?, ?)";
            $stmt = $this->pdo->prepare($sql);

            return $stmt->execute([$jti, $revokedAt, $expiresAt]);
        }

        // MySQL: INSERT ... ON DUPLICATE KEY UPDATE
        $sql = "INSERT INTO {$blacklistTable} (jti, revoked_at, expires_at) VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE revoked_at = VALUES(revoked_at), expires_at = VALUES(expires_at)";
        $stmt = $this->pdo->prepare($sql);

        return $stmt->execute([$jti, $revokedAt, $expiresAt]);
    }

    /**
     * 检查键是否在黑名单中
     *
     * @param string $jti JWT ID
     * @return bool
     */
    public function isBlacklisted(string $jti): bool
    {
        // 概率触发过期清理，避免每次读都全表扫描
        $this->maybeCleanExpired();

        $blacklistTable = $this->table . '_blacklist';
        $sql = "SELECT COUNT(*) FROM {$blacklistTable} WHERE jti = ?";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$jti]);
        $count = $stmt->fetchColumn();

        return $count > 0;
    }

    public function removeFromBlacklist(string $jti): bool
    {
        $blacklistTable = $this->table . '_blacklist';
        $sql = "DELETE FROM {$blacklistTable} WHERE jti = ?";
        $stmt = $this->pdo->prepare($sql);

        return $stmt->execute([$jti]);
    }

    /**
     * 概率触发过期清理（1% 概率）
     *
     * 避免每次读操作都执行全表清理，影响读性能。
     */
    protected function maybeCleanExpired(): void
    {
        if (mt_rand(1, 100) === 1) {
            $this->cleanExpired();
        }
    }

    /**
     * 清理过期项
     *
     * @return int 清理的记录数量
     */
    public function cleanExpired(): int
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
        $tokenCount = $stmt === false ? 0 : (int) $stmt->fetchColumn();

        $blacklistTable = $this->table . '_blacklist';
        $sql = "SELECT COUNT(*) as count FROM {$blacklistTable}";
        $stmt = $this->pdo->query($sql);
        $blacklistCount = $stmt === false ? 0 : (int) $stmt->fetchColumn();

        return [
            'type' => 'database',
            'driver' => $this->driver,
            'table' => $this->table,
            'token_count' => $tokenCount,
            'blacklist_count' => $blacklistCount,
        ];
    }

    /**
     * 延长键的过期时间
     *
     * @param string $key 键名
     * @param int $ttl 新的过期时间（秒），0 表示永不过期
     * @return bool
     */
    public function touch(string $key, int $ttl): bool
    {
        $sql = "SELECT expires_at FROM {$this->table} WHERE token_key = ?";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$key]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        // 键不存在
        if ($result === false) {
            return false;
        }

        $expiresAt = (int) $result['expires_at'];

        // 已过期的键不能续期，先删除
        if ($expiresAt > 0 && $expiresAt < time()) {
            $this->delete($key);
            return false;
        }

        $newExpiresAt = $ttl > 0 ? time() + $ttl : 0;
        $sql = "UPDATE {$this->table} SET expires_at = ? WHERE token_key = ?";
        $stmt = $this->pdo->prepare($sql);
        $executed = $stmt->execute([$newExpiresAt, $key]);

        return $executed && $stmt->rowCount() > 0;
    }

    /**
     * 获取键的剩余过期时间（秒）
     *
     * @param string $key 键名
     * @return int 剩余秒数，-2 表示键不存在，-1 表示永不过期
     */
    public function getRemainingTtl(string $key): int
    {
        $sql = "SELECT expires_at FROM {$this->table} WHERE token_key = ?";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$key]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        // 键不存在
        if ($result === false) {
            return -2;
        }

        $expiresAt = (int) $result['expires_at'];

        // 永不过期
        if ($expiresAt <= 0) {
            return -1;
        }

        $remaining = $expiresAt - time();
        return $remaining > 0 ? $remaining : -2;
    }

    /**
     * 清空存储
     *
     * 清空 token 表和黑名单表中的所有记录。
     *
     * @return bool
     */
    public function clear(): bool
    {
        $success = true;

        $sql = "DELETE FROM {$this->table}";
        if ($this->pdo->exec($sql) === false) {
            $success = false;
        }

        $blacklistTable = $this->table . '_blacklist';
        $sql = "DELETE FROM {$blacklistTable}";
        if ($this->pdo->exec($sql) === false) {
            $success = false;
        }

        return $success;
    }

    /**
     * 获取PDO实例
     *
     * @return PDO
     */
    public function getPdo(): PDO
    {
        return $this->pdo;
    }

    /**
     * 原子化撤销 Token
     *
     * 一次性完成以下四步：
     *   1. 将 JTI 加入黑名单
     *   2. 如果 SSO 映射匹配则清理 SSO 标记
     *   3. 从用户活跃 Token 列表中移除 JTI
     *   4. 删除 Token 详情键
     *
     * @param string $jti      JWT ID
     * @param string $uid      用户 ID
     * @param string $platform 平台标识
     * @param int    $ttl      黑名单保留时间（秒）
     * @return int 受影响键数量
     */
    public function atomicRevoke(string $jti, string $uid, string $platform, int $ttl = 3600): int
    {
        $count = 0;

        // 1. 将 JTI 加入黑名单
        if ($this->blacklist($jti, $ttl)) {
            $count++;
        }

        // 2. 如果 SSO 映射匹配则清理 SSO 标记
        $ssoKey = "sso:{$uid}:{$platform}";
        if ($this->get($ssoKey) === $jti) {
            if ($this->delete($ssoKey)) {
                $count++;
            }
        }

        // 3. 从用户活跃 Token 列表中移除 JTI
        $listKey = "user:{$uid}:{$platform}:tokens";
        $list = (array) $this->get($listKey, []);
        if (in_array($jti, $list, true)) {
            $list = array_values(array_filter($list, static fn(string $x): bool => $x !== $jti));
            $this->set($listKey, $list, $ttl);
            $count++;
        }

        // 4. 删除 Token 详情键
        if ($this->delete("token:{$jti}")) {
            $count++;
        }

        return $count;
    }

    /**
     * 记录到用户活跃 Token 列表
     *
     * 列表默认仅保留最近 50 条以避免无限增长。
     *
     * @param string $uid      用户 ID
     * @param string $platform 平台标识
     * @param string $jti      JWT ID
     * @param int    $ttl      列表保留时间（秒）
     * @return bool
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
     *
     * @param string $uid      用户 ID
     * @param string $platform 平台标识
     * @param string $jti      JWT ID
     * @param int    $ttl      映射保留时间（秒）
     * @return bool
     */
    public function setSsoMapping(string $uid, string $platform, string $jti, int $ttl = 0): bool
    {
        return $this->set("sso:{$uid}:{$platform}", $jti, $ttl);
    }

    /**
     * 获取 SSO 平台 → JTI 映射
     *
     * @param string $uid      用户 ID
     * @param string $platform 平台标识
     * @return string|null JTI，不存在时返回 null
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
