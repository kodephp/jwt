<?php

namespace Kode\Jwt\Tests\Storage;

use Kode\Jwt\Tests\TestCase;
use Kode\Jwt\Storage\MemoryStorage;

class MemoryStorageTest extends TestCase
{
    private MemoryStorage $storage;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = new MemoryStorage(['limit' => 100]);
    }

    public function testSetAndGet()
    {
        $result = $this->storage->set('test_key', 'test_value', 3600);
        $this->assertTrue($result);

        $value = $this->storage->get('test_key');
        $this->assertEquals('test_value', $value);
    }

    public function testDelete()
    {
        $this->storage->set('test_key', 'test_value', 3600);
        
        $result = $this->storage->delete('test_key');
        $this->assertTrue($result);

        $value = $this->storage->get('test_key');
        $this->assertNull($value);
    }

    public function testBlacklist()
    {
        $result = $this->storage->blacklist('test_jti', 3600);
        $this->assertTrue($result);

        $isBlacklisted = $this->storage->isBlacklisted('test_jti');
        $this->assertTrue($isBlacklisted);
    }

    public function testCleanExpired()
    {
        $this->storage->set('expired_key', 'expired_value', 1); // 1秒过期
        sleep(2); // 等待过期
        
        $result = $this->storage->cleanExpired();
        $this->assertTrue($result);

        $value = $this->storage->get('expired_key');
        $this->assertNull($value);
    }
}