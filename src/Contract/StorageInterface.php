<?php

declare(strict_types=1);

namespace Kode\Jwt\Contract;

interface StorageInterface
{
    public function set(string $key, mixed $value, int $ttl = 3600): bool;

    public function get(string $key, mixed $default = null): mixed;

    public function delete(string $key): bool;

    public function has(string $key): bool;

    public function setMultiple(array $values, int $ttl = 0): bool;

    public function getMultiple(array $keys, mixed $default = null): array;

    public function deleteMultiple(array $keys): bool;

    public function getStats(): array;

    public function blacklist(string $jti, int $ttl = 3600): bool;

    public function isBlacklisted(string $jti): bool;

    public function cleanExpired(): bool|int;

    public function touch(string $key, int $ttl): bool;

    public function getRemainingTtl(string $key): int;

    public function clear(): bool;
}
