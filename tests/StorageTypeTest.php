<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Enum\StorageType;
use PHPUnit\Framework\TestCase;

final class StorageTypeTest extends TestCase
{
    public function testPersistentStorageTypes(): void
    {
        self::assertTrue(StorageType::REDIS->isPersistent());
        self::assertTrue(StorageType::FILE->isPersistent());
        self::assertTrue(StorageType::APCU->isPersistent());
        self::assertTrue(StorageType::MEMCACHED->isPersistent());
        self::assertTrue(StorageType::DATABASE->isPersistent());

        self::assertFalse(StorageType::MEMORY->isPersistent());
        self::assertFalse(StorageType::NULL->isPersistent());
    }

    public function testCacheStorageTypes(): void
    {
        self::assertTrue(StorageType::MEMORY->isCache());
        self::assertTrue(StorageType::APCU->isCache());
        self::assertTrue(StorageType::MEMCACHED->isCache());

        self::assertFalse(StorageType::REDIS->isCache());
        self::assertFalse(StorageType::FILE->isCache());
        self::assertFalse(StorageType::DATABASE->isCache());
    }

    public function testRequiresExtension(): void
    {
        self::assertSame('ext-redis', StorageType::REDIS->requiresExtension());
        self::assertSame('ext-apcu', StorageType::APCU->requiresExtension());
        self::assertSame('ext-memcached', StorageType::MEMCACHED->requiresExtension());
        self::assertSame('ext-pdo', StorageType::DATABASE->requiresExtension());
        self::assertNull(StorageType::MEMORY->requiresExtension());
        self::assertNull(StorageType::FILE->requiresExtension());
        self::assertNull(StorageType::NULL->requiresExtension());
    }

    public function testFromString(): void
    {
        self::assertSame(StorageType::MEMORY, StorageType::fromString('memory'));
        self::assertSame(StorageType::MEMORY, StorageType::fromString('MEM'));
        self::assertSame(StorageType::REDIS, StorageType::fromString('redis'));
        self::assertSame(StorageType::FILE, StorageType::fromString('file'));
        self::assertSame(StorageType::FILE, StorageType::fromString('filesystem'));
        self::assertSame(StorageType::APCU, StorageType::fromString('apcu'));
        self::assertSame(StorageType::MEMCACHED, StorageType::fromString('memcached'));
        self::assertSame(StorageType::DATABASE, StorageType::fromString('database'));
        self::assertSame(StorageType::NULL, StorageType::fromString('null'));
    }

    public function testFromStringThrowsOnInvalid(): void
    {
        $this->expectException(\ValueError::class);
        $this->expectExceptionMessage('Unknown storage type');

        StorageType::fromString('invalid');
    }
}
