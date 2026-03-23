<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\KeyRotation\KeyRotationManager;
use Kode\Jwt\KeyRotation\KeyVersion;
use Kode\Jwt\Storage\MemoryStorage;
use PHPUnit\Framework\TestCase;

final class KeyRotationTest extends TestCase
{
    private MemoryStorage $storage;

    private KeyRotationManager $manager;

    protected function setUp(): void
    {
        $this->storage = new MemoryStorage(['limit' => 100]);
        $this->manager = new KeyRotationManager(
            $this->storage,
            'hmac',
            3600,
            1800
        );
    }

    public function testGenerateNewKey(): void
    {
        $key = $this->manager->generateNewKey();

        self::assertNotEmpty($key->keyId);
        self::assertNotEmpty($key->key);
        self::assertTrue($key->isActive);
        self::assertTrue($key->isPrimary);
        self::assertFalse($key->isExpired());
    }

    public function testGetPrimaryKey(): void
    {
        $key = $this->manager->generateNewKey();

        $primary = $this->manager->getPrimaryKey();

        self::assertNotNull($primary);
        self::assertSame($key->keyId, $primary->keyId);
    }

    public function testGetKeyById(): void
    {
        $key = $this->manager->generateNewKey();

        $retrieved = $this->manager->getKeyById($key->keyId);

        self::assertNotNull($retrieved);
        self::assertSame($key->keyId, $retrieved->keyId);
    }

    public function testGetSigningKey(): void
    {
        $this->manager->generateNewKey();

        $signingKey = $this->manager->getSigningKey();

        self::assertNotNull($signingKey);
        self::assertTrue($signingKey->isPrimary);
    }

    public function testGetVerificationKeys(): void
    {
        $this->manager->generateNewKey();

        $keys = $this->manager->getVerificationKeys();

        self::assertCount(1, $keys);
    }

    public function testRevokeKey(): void
    {
        $key = $this->manager->generateNewKey();

        $result = $this->manager->revokeKey($key->keyId);

        self::assertTrue($result);

        $revoked = $this->manager->getKeyById($key->keyId);
        self::assertFalse($revoked->isActive);
    }

    public function testGetRotationStatus(): void
    {
        $this->manager->generateNewKey();

        $status = $this->manager->getRotationStatus();

        self::assertArrayHasKey('total_keys', $status);
        self::assertArrayHasKey('valid_keys', $status);
        self::assertArrayHasKey('has_primary', $status);
        self::assertTrue($status['has_primary']);
    }

    public function testKeyVersionIsExpired(): void
    {
        $expiredKey = new KeyVersion(
            keyId: 'expired_key',
            key: 'test_key',
            createdAt: time() - 7200,
            expiresAt: time() - 3600,
            isActive: true,
            isPrimary: false
        );

        self::assertTrue($expiredKey->isExpired());
    }

    public function testKeyVersionIsUsable(): void
    {
        $validKey = new KeyVersion(
            keyId: 'valid_key',
            key: 'test_key',
            createdAt: time(),
            expiresAt: time() + 3600,
            isActive: true,
            isPrimary: true
        );

        self::assertTrue($validKey->isUsable());
    }

    public function testKeyVersionGetRemainingTtl(): void
    {
        $key = new KeyVersion(
            keyId: 'test_key',
            key: 'test_key',
            createdAt: time(),
            expiresAt: time() + 3600,
            isActive: true,
            isPrimary: true
        );

        $ttl = $key->getRemainingTtl();

        self::assertGreaterThan(0, $ttl);
        self::assertLessThanOrEqual(3600, $ttl);
    }

    public function testKeyVersionFromArray(): void
    {
        $data = [
            'key_id' => 'test_id',
            'key' => 'test_key',
            'created_at' => time(),
            'expires_at' => time() + 3600,
            'is_active' => true,
            'is_primary' => true,
        ];

        $key = KeyVersion::fromArray($data);

        self::assertSame('test_id', $key->keyId);
        self::assertSame('test_key', $key->key);
    }

    public function testKeyVersionToArray(): void
    {
        $key = new KeyVersion(
            keyId: 'test_id',
            key: 'test_key',
            createdAt: time(),
            expiresAt: time() + 3600,
            isActive: true,
            isPrimary: true
        );

        $array = $key->toArray();

        self::assertSame('test_id', $array['key_id']);
        self::assertSame('test_key', $array['key']);
        self::assertTrue($array['is_active']);
        self::assertTrue($array['is_primary']);
    }
}
