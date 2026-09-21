<?php

declare(strict_types=1);

namespace Kode\Jwt\Storage;

use Kode\Jwt\Contract\SsoStorageInterface;
use Kode\Jwt\Contract\StorageInterface;

class MemoryStorage implements SsoStorageInterface
{
    /** 黑名单条数硬上限（可经 config['blacklist_limit'] 调整） */
    public const DEFAULT_BLACKLIST_LIMIT = 100_000;

    /**
     * @var array<string, array{value: mixed, expires_at: int}>
     */
    protected array $storage = [];

    /**
     * @var array<string, int>
     */
    protected array $blacklist = [];

    protected int $limit;

    protected int $blacklistLimit;

    public function __construct(array $config = [])
    {
        $this->limit = $config['limit'] ?? 10000;
        $this->blacklistLimit = max(1000, (int) ($config['blacklist_limit'] ?? self::DEFAULT_BLACKLIST_LIMIT));
    }

    public function set(string $key, mixed $value, int $ttl = 0): bool
    {
        if (count($this->storage) >= $this->limit) {
            array_shift($this->storage);
        }

        $this->storage[$key] = [
            'value' => $value,
            'expires_at' => $ttl <= 0 ? 0 : time() + $ttl,
        ];

        return true;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        if (!isset($this->storage[$key])) {
            return $default;
        }

        $item = $this->storage[$key];

        if ($item['expires_at'] > 0 && time() > $item['expires_at']) {
            unset($this->storage[$key]);
            return $default;
        }

        return $item['value'];
    }

    public function delete(string $key): bool
    {
        unset($this->storage[$key]);
        return true;
    }

    public function has(string $key): bool
    {
        if (!isset($this->storage[$key])) {
            return false;
        }

        $item = $this->storage[$key];

        if ($item['expires_at'] > 0 && time() > $item['expires_at']) {
            unset($this->storage[$key]);
            return false;
        }

        return true;
    }

    public function setMultiple(array $values, int $ttl = 0): bool
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value, $ttl);
        }

        return true;
    }

    public function getMultiple(array $keys, mixed $default = null): array
    {
        $results = [];

        foreach ($keys as $key) {
            $results[$key] = $this->get($key, $default);
        }

        return $results;
    }

    public function deleteMultiple(array $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function blacklist(string $jti, int $ttl = 3600): bool
    {
        if (count($this->blacklist) >= $this->blacklistLimit) {
            $this->trimBlacklist();
        }

        $this->blacklist[$jti] = time() + $ttl;
        return true;
    }

    /**
     * 常驻进程内的黑名单只随查删是收不拢的（jti 高熵不复用），
     * 触顶时先清已过期项，仍超则按最早到期逐个放行——等价于提前自然过期。
     */
    private function trimBlacklist(): void
    {
        $now = time();
        foreach ($this->blacklist as $jti => $expiresAt) {
            if ($expiresAt <= $now) {
                unset($this->blacklist[$jti]);
            }
        }

        $overflow = count($this->blacklist) - $this->blacklistLimit + 1;
        if ($overflow > 0) {
            asort($this->blacklist);
            foreach (array_slice(array_keys($this->blacklist), 0, $overflow) as $jti) {
                unset($this->blacklist[$jti]);
            }
        }
    }

    public function isBlacklisted(string $jti): bool
    {
        if (!isset($this->blacklist[$jti])) {
            return false;
        }

        if (time() > $this->blacklist[$jti]) {
            unset($this->blacklist[$jti]);
            return false;
        }

        return true;
    }

    public function removeFromBlacklist(string $jti): bool
    {
        unset($this->blacklist[$jti]);
        return true;
    }

    public function cleanExpired(): bool|int
    {
        $count = 0;
        $now = time();

        foreach ($this->storage as $key => $item) {
            if ($item['expires_at'] > 0 && $now > $item['expires_at']) {
                unset($this->storage[$key]);
                $count++;
            }
        }

        foreach ($this->blacklist as $jti => $expiresAt) {
            if ($now > $expiresAt) {
                unset($this->blacklist[$jti]);
                $count++;
            }
        }

        return $count;
    }

    public function getStats(): array
    {
        $this->cleanExpired();

        return [
            'storage_count' => count($this->storage),
            'blacklist_count' => count($this->blacklist),
            'limit' => $this->limit,
            'memory_usage' => memory_get_usage(true),
        ];
    }

    public function touch(string $key, int $ttl): bool
    {
        if (!isset($this->storage[$key])) {
            return false;
        }

        $item = $this->storage[$key];

        if ($item['expires_at'] > 0 && time() > $item['expires_at']) {
            unset($this->storage[$key]);
            return false;
        }

        $this->storage[$key]['expires_at'] = time() + $ttl;
        return true;
    }

    public function getRemainingTtl(string $key): int
    {
        if (!isset($this->storage[$key])) {
            return -2;
        }

        $item = $this->storage[$key];

        if ($item['expires_at'] <= 0) {
            return -1;
        }

        $remaining = $item['expires_at'] - time();
        return $remaining > 0 ? $remaining : -2;
    }

    public function clear(): bool
    {
        $this->storage = [];
        $this->blacklist = [];
        return true;
    }

    /**
     * 内存存储原子化撤销（兼容接口）
     *
     * 内存环境下没有并发问题，可顺序执行：黑名单 → SSO 清理 → 用户列表清理。
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
