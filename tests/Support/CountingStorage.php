<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests\Support;

use Kode\Jwt\Contract\SsoStorageInterface;
use Kode\Jwt\Contract\StorageInterface;

/**
 * 记账用的存储装饰器：把每一枚 `get()` / `getMultiple()` 的键名留下来。
 *
 * 存在的理由：「撤销一个账号」的成本不是能不能撤销，而是**几次往返**。
 * 断言「结果对」挡不住「七个平台各问一次」——那种写法每一条都问得到、每一条都对，
 * 只是把一次点击摊成 7 次串行网络往返（乘上账号数就是几十万次）。
 * 所以这一族的判据只能打在调用序列上。
 *
 * 只记门面这一层：被包住的驱动自己内部的读（例如 MemoryStorage::trackUserToken
 * 里的 `$this->get()`）不经过这里，那是驱动的实现细节，不是调用方的预算。
 */
final class CountingStorage implements SsoStorageInterface
{
    /** @var list<array{op: string, keys: list<string>}> */
    private array $reads = [];

    public function __construct(private readonly StorageInterface $inner)
    {
    }

    // ---------------------------------------------------------------- 记账面

    /**
     * @return list<array{op: string, keys: list<string>}>
     */
    public function reads(): array
    {
        return $this->reads;
    }

    /**
     * 某一类读的总次数。
     *
     * @param 'get'|'getMultiple' $op
     */
    public function countOf(string $op): int
    {
        $n = 0;
        foreach ($this->reads as $read) {
            if ($read['op'] === $op) {
                $n++;
            }
        }

        return $n;
    }

    /**
     * 抹掉已记的账：让夹具的写入阶段（签发）不进用例的预算。
     */
    public function resetReads(): void
    {
        $this->reads = [];
    }

    /**
     * 「按 `get()` 逐枚读过哪些键」——批量化的回归就是把这批键读没了。
     *
     * @return list<string>
     */
    public function singleReadKeys(): array
    {
        return $this->keysOf('get');
    }

    /**
     * @param 'get'|'getMultiple' $op
     * @return list<string>
     */
    public function keysOf(string $op): array
    {
        $keys = [];
        foreach ($this->reads as $read) {
            if ($read['op'] === $op) {
                $keys = array_merge($keys, $read['keys']);
            }
        }

        return $keys;
    }

    /**
     * @param array<string> $keys
     */
    private function note(string $op, array $keys): void
    {
        $this->reads[] = ['op' => $op, 'keys' => array_values($keys)];
    }

    // -------------------------------------------------------------- 门面转发

    public function set(string $key, mixed $value, int $ttl = 0): bool
    {
        return $this->inner->set($key, $value, $ttl);
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $this->note('get', [$key]);

        return $this->inner->get($key, $default);
    }

    public function delete(string $key): bool
    {
        return $this->inner->delete($key);
    }

    public function has(string $key): bool
    {
        return $this->inner->has($key);
    }

    public function setMultiple(array $values, int $ttl = 0): bool
    {
        return $this->inner->setMultiple($values, $ttl);
    }

    public function getMultiple(array $keys, mixed $default = null): array
    {
        $this->note('getMultiple', $keys);

        return $this->inner->getMultiple($keys, $default);
    }

    public function deleteMultiple(array $keys): bool
    {
        return $this->inner->deleteMultiple($keys);
    }

    public function getStats(): array
    {
        return $this->inner->getStats();
    }

    public function blacklist(string $jti, int $ttl = 3600): bool
    {
        return $this->inner->blacklist($jti, $ttl);
    }

    public function isBlacklisted(string $jti): bool
    {
        return $this->inner->isBlacklisted($jti);
    }

    public function removeFromBlacklist(string $jti): bool
    {
        return $this->inner->removeFromBlacklist($jti);
    }

    public function cleanExpired(): bool|int
    {
        return $this->inner->cleanExpired();
    }

    public function touch(string $key, int $ttl): bool
    {
        return $this->inner->touch($key, $ttl);
    }

    public function getRemainingTtl(string $key): int
    {
        return $this->inner->getRemainingTtl($key);
    }

    public function clear(): bool
    {
        return $this->inner->clear();
    }

    public function atomicRevoke(string $jti, string $uid, string $platform, int $ttl = 3600): int
    {
        /** @var SsoStorageInterface $inner */
        $inner = $this->inner;

        return $inner->atomicRevoke($jti, $uid, $platform, $ttl);
    }

    public function trackUserToken(string $uid, string $platform, string $jti, int $ttl = 0): bool
    {
        /** @var SsoStorageInterface $inner */
        $inner = $this->inner;

        return $inner->trackUserToken($uid, $platform, $jti, $ttl);
    }

    public function setSsoMapping(string $uid, string $platform, string $jti, int $ttl = 0): bool
    {
        /** @var SsoStorageInterface $inner */
        $inner = $this->inner;

        return $inner->setSsoMapping($uid, $platform, $jti, $ttl);
    }

    public function getSsoMapping(string $uid, string $platform): ?string
    {
        /** @var SsoStorageInterface $inner */
        $inner = $this->inner;

        return $inner->getSsoMapping($uid, $platform);
    }
}
