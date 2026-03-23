<?php

declare(strict_types=1);

namespace Kode\Jwt\Enum;

enum StorageType: string
{
    case MEMORY = 'memory';
    case REDIS = 'redis';
    case FILE = 'file';
    case APCU = 'apcu';
    case MEMCACHED = 'memcached';
    case DATABASE = 'database';
    case NULL = 'null';

    public function isPersistent(): bool
    {
        return match ($this) {
            self::REDIS, self::FILE, self::APCU, self::MEMCACHED, self::DATABASE => true,
            self::MEMORY, self::NULL => false,
        };
    }

    public function isCache(): bool
    {
        return match ($this) {
            self::MEMORY, self::APCU, self::MEMCACHED => true,
            default => false,
        };
    }

    public function requiresExtension(): ?string
    {
        return match ($this) {
            self::REDIS => 'ext-redis',
            self::APCU => 'ext-apcu',
            self::MEMCACHED => 'ext-memcached',
            self::DATABASE => 'ext-pdo',
            default => null,
        };
    }

    public function getDescription(): string
    {
        return match ($this) {
            self::MEMORY => 'In-memory storage (non-persistent, fast)',
            self::REDIS => 'Redis storage (persistent, distributed)',
            self::FILE => 'File-based storage (persistent, local)',
            self::APCU => 'APCu storage (persistent, shared memory)',
            self::MEMCACHED => 'Memcached storage (persistent, distributed)',
            self::DATABASE => 'Database storage (persistent, RDBMS)',
            self::NULL => 'Null storage (no-op, for testing)',
        };
    }

    public static function fromString(string $type): self
    {
        $normalized = strtolower(trim($type));

        return match ($normalized) {
            'memory', 'mem' => self::MEMORY,
            'redis' => self::REDIS,
            'file', 'filesystem' => self::FILE,
            'apcu', 'apc' => self::APCU,
            'memcached', 'memcache' => self::MEMCACHED,
            'database', 'db', 'pdo' => self::DATABASE,
            'null', 'none' => self::NULL,
            default => throw new \ValueError("Unknown storage type: {$type}"),
        };
    }
}
