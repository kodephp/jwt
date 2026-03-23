<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Storage\MemoryStorage;
use PHPUnit\Framework\TestCase;

final class MemoryStorageTest extends TestCase
{
    private MemoryStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new MemoryStorage(['limit' => 100]);
    }

    public function testSetAndGet(): void
    {
        self::assertTrue($this->storage->set('key1', 'value1', 3600));
        self::assertSame('value1', $this->storage->get('key1'));
    }

    public function testGetDefault(): void
    {
        self::assertSame('default', $this->storage->get('nonexistent', 'default'));
    }

    public function testHas(): void
    {
        $this->storage->set('key1', 'value1');

        self::assertTrue($this->storage->has('key1'));
        self::assertFalse($this->storage->has('nonexistent'));
    }

    public function testDelete(): void
    {
        $this->storage->set('key1', 'value1');
        self::assertTrue($this->storage->delete('key1'));
        self::assertFalse($this->storage->has('key1'));
    }

    public function testSetMultiple(): void
    {
        $values = ['key1' => 'value1', 'key2' => 'value2'];
        self::assertTrue($this->storage->setMultiple($values, 3600));

        self::assertSame('value1', $this->storage->get('key1'));
        self::assertSame('value2', $this->storage->get('key2'));
    }

    public function testGetMultiple(): void
    {
        $this->storage->set('key1', 'value1');
        $this->storage->set('key2', 'value2');

        $results = $this->storage->getMultiple(['key1', 'key2', 'key3'], 'default');

        self::assertSame('value1', $results['key1']);
        self::assertSame('value2', $results['key2']);
        self::assertSame('default', $results['key3']);
    }

    public function testDeleteMultiple(): void
    {
        $this->storage->setMultiple(['key1' => 'value1', 'key2' => 'value2']);
        self::assertTrue($this->storage->deleteMultiple(['key1', 'key2']));

        self::assertFalse($this->storage->has('key1'));
        self::assertFalse($this->storage->has('key2'));
    }

    public function testBlacklist(): void
    {
        self::assertFalse($this->storage->isBlacklisted('jti1'));

        $this->storage->blacklist('jti1', 3600);

        self::assertTrue($this->storage->isBlacklisted('jti1'));
    }

    public function testIsNotBlacklistedWhenExpired(): void
    {
        $this->storage->blacklist('jti_expired', -1);

        self::assertFalse($this->storage->isBlacklisted('jti_expired'));
    }

    public function testCleanExpiredDoesNotRemoveNoExpiryItems(): void
    {
        $this->storage->set('key1', 'value1', 0);
        $this->storage->set('key2', 'value2', 3600);

        $count = $this->storage->cleanExpired();

        self::assertSame(0, $count);
        self::assertTrue($this->storage->has('key1'));
        self::assertTrue($this->storage->has('key2'));
    }

    public function testGetStats(): void
    {
        $this->storage->set('key1', 'value1');
        $this->storage->blacklist('jti1');

        $stats = $this->storage->getStats();

        self::assertSame(1, $stats['storage_count']);
        self::assertSame(1, $stats['blacklist_count']);
        self::assertSame(100, $stats['limit']);
        self::assertArrayHasKey('memory_usage', $stats);
    }

    public function testTouch(): void
    {
        $this->storage->set('key1', 'value1', 3600);
        self::assertTrue($this->storage->touch('key1', 7200));

        $ttl = $this->storage->getRemainingTtl('key1');
        self::assertGreaterThanOrEqual(7199, $ttl);
    }

    public function testTouchReturnsFalseForNonexistent(): void
    {
        self::assertFalse($this->storage->touch('nonexistent', 3600));
    }

    public function testGetRemainingTtl(): void
    {
        $this->storage->set('key1', 'value1', 3600);

        $ttl = $this->storage->getRemainingTtl('key1');
        self::assertGreaterThanOrEqual(3599, $ttl);
        self::assertLessThanOrEqual(3600, $ttl);
    }

    public function testGetRemainingTtlReturnsNegativeForNonexistent(): void
    {
        self::assertSame(-2, $this->storage->getRemainingTtl('nonexistent'));
    }

    public function testGetRemainingTtlReturnsNegativeForNoExpiry(): void
    {
        $this->storage->set('key1', 'value1', 0);

        self::assertSame(-1, $this->storage->getRemainingTtl('key1'));
    }

    public function testClear(): void
    {
        $this->storage->setMultiple(['key1' => 'value1', 'key2' => 'value2']);
        $this->storage->blacklist('jti1');

        self::assertTrue($this->storage->clear());

        self::assertFalse($this->storage->has('key1'));
        self::assertFalse($this->storage->has('key2'));
        self::assertFalse($this->storage->isBlacklisted('jti1'));
    }
}
