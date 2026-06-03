<?php

declare(strict_types=1);

namespace Kode\Jwt\Stub;

/**
 * ext-redis 扩展的 IDE 存根类
 *
 * 在未安装 ext-redis 的开发环境中提供类型声明。
 * 运行时由 ext-redis 真实类接管。
 *
 * 仅为 IDE 静态分析使用，真实运行请确保已安装 ext-redis 扩展。
 */
class RedisStub
{
    public const OPT_READ_TIMEOUT = 0;
    public const PIPELINE = 1;
    public const ATOMIC = 2;
    public const MULTI = 3;
    public const SERIALIZER_NONE = 0;
    public const SERIALIZER_PHP = 1;
    public const COMPRESSION_NONE = 0;

    public function __construct() {}

    /** @param string|array<string, mixed> ...$args */
    public function connect(...$args): bool { return true; }

    /** @param string|array<string, mixed> ...$args */
    public function pconnect(...$args): bool { return true; }

    public function auth(string $password): bool { return true; }

    public function select(int $db): bool { return true; }

    public function setOption(int $name, mixed $value): bool { return true; }

    public function getOption(int $name): mixed { return null; }

    public function ping(): bool { return true; }

    public function close(): bool { return true; }

    public function get(string $key): mixed { return false; }

    public function set(string $key, mixed $value, mixed $options = null): mixed { return true; }

    public function setex(string $key, int $ttl, mixed $value): bool { return true; }

    public function psetex(string $key, int $ttl, mixed $value): bool { return true; }

    public function exists(string|array $keys): int { return 0; }

    public function del(string|array $keys): int { return 0; }

    public function delete(string|array $keys): int { return 0; }

    public function expire(string $key, int $ttl): bool { return true; }

    public function ttl(string $key): int { return -2; }

    public function pttl(string $key): int { return -2; }

    public function incr(string $key): int { return 0; }

    public function decr(string $key): int { return 0; }

    public function incrBy(string $key, int $value): int { return 0; }

    public function decrBy(string $key, int $value): int { return 0; }

    public function lPush(string $key, mixed ...$values): int { return 0; }

    public function rPush(string $key, mixed ...$values): int { return 0; }

    public function lPop(string $key): mixed { return null; }

    public function rPop(string $key): mixed { return null; }

    public function lLen(string $key): int { return 0; }

    public function lRange(string $key, int $start, int $stop): array { return []; }

    public function lTrim(string $key, int $start, int $stop): bool { return true; }

    public function lRem(string $key, mixed $value, int $count = 0): int { return 0; }

    public function sAdd(string $key, mixed ...$values): int { return 0; }

    public function sRem(string $key, mixed ...$values): int { return 0; }

    public function sMembers(string $key): array { return []; }

    public function sCard(string $key): int { return 0; }

    public function sIsMember(string $key, mixed $value): bool { return false; }

    public function zAdd(string $key, float $score, mixed $member, ...$args): int { return 0; }

    public function zRem(string $key, mixed $member): int { return 0; }

    public function zRemRangeByScore(string $key, string $min, string $max): int { return 0; }

    public function zCard(string $key): int { return 0; }

    public function zRange(string $key, int $start, int $stop, bool $withScores = false): array { return []; }

    public function keys(string $pattern): array { return []; }

    public function mget(array $keys): array { return []; }

    public function mset(array $values): bool { return true; }

    /** @param string|array $scriptOrKeys */
    public function eval($scriptOrKeys, array $args = [], int $numKeys = 0): mixed { return null; }

    public function multi(int $mode = self::PIPELINE): bool|self
    {
        return $this;
    }

    public function exec(): array { return []; }

    public function discard(): bool { return true; }

    public function watch(string|array $keys): bool { return true; }
}

if (!class_exists('Redis', false)) {
    class_alias(RedisStub::class, 'Redis');
}
