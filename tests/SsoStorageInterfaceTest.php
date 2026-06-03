<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Contract\SsoStorageInterface;
use Kode\Jwt\Storage\MemoryStorage;
use PHPUnit\Framework\TestCase;

/**
 * SsoStorageInterface 增强能力测试
 */
final class SsoStorageInterfaceTest extends TestCase
{
    private MemoryStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new MemoryStorage();
    }

    public function testImplementsInterface(): void
    {
        self::assertInstanceOf(SsoStorageInterface::class, $this->storage);
    }

    public function testSsoMappingRoundTrip(): void
    {
        $this->assertTrue($this->storage->setSsoMapping('1001', 'web', 'jti_abc', 3600));
        self::assertSame('jti_abc', $this->storage->getSsoMapping('1001', 'web'));
    }

    public function testGetSsoMappingReturnsNullWhenMissing(): void
    {
        self::assertNull($this->storage->getSsoMapping('1001', 'web'));
    }

    public function testTrackUserTokenPersistsList(): void
    {
        $this->assertTrue($this->storage->trackUserToken('1001', 'web', 'jti_a', 3600));
        $this->assertTrue($this->storage->trackUserToken('1001', 'web', 'jti_b', 3600));
        $list = (array) $this->storage->get('user:1001:web:tokens', []);
        self::assertContains('jti_a', $list);
        self::assertContains('jti_b', $list);
    }

    public function testTrackUserTokenDeduplicates(): void
    {
        $this->storage->trackUserToken('1001', 'web', 'jti_a', 3600);
        $this->storage->trackUserToken('1001', 'web', 'jti_a', 3600);
        $list = (array) $this->storage->get('user:1001:web:tokens', []);
        self::assertCount(1, $list, '同一 JTI 不应重复记录');
    }

    public function testTrackUserTokenLimitsTo50(): void
    {
        for ($i = 0; $i < 60; $i++) {
            $this->storage->trackUserToken('1001', 'web', "jti_{$i}", 3600);
        }
        $list = (array) $this->storage->get('user:1001:web:tokens', []);
        self::assertCount(50, $list, '活跃 Token 列表应限制在 50 条以内');
    }

    public function testAtomicRevokeCleansAllRelatedKeys(): void
    {
        // 准备数据
        $this->storage->setSsoMapping('1001', 'web', 'jti_target', 3600);
        $this->storage->trackUserToken('1001', 'web', 'jti_target', 3600);
        $this->storage->blacklist('jti_target', 3600);

        // 执行原子化撤销（实际上 MemoryStorage 的 atomicRevoke 是顺序执行，行为等价于一组操作）
        $affected = $this->storage->atomicRevoke('jti_target', '1001', 'web', 3600);

        self::assertGreaterThan(0, $affected);
        // SSO 映射应当被清理
        self::assertNull($this->storage->getSsoMapping('1001', 'web'));
        // 用户活跃列表应当不含该 JTI
        $list = (array) $this->storage->get('user:1001:web:tokens', []);
        self::assertNotContains('jti_target', $list);
    }

    public function testAtomicRevokeLeavesOtherSsoUnaffected(): void
    {
        // 准备两个 SSO 映射
        $this->storage->setSsoMapping('1001', 'web', 'jti_target', 3600);
        $this->storage->setSsoMapping('1001', 'mobile', 'jti_other', 3600);

        $this->storage->atomicRevoke('jti_target', '1001', 'web', 3600);

        // 目标 SSO 应当被清理
        self::assertNull($this->storage->getSsoMapping('1001', 'web'));
        // 其他 SSO 保持不变
        self::assertSame('jti_other', $this->storage->getSsoMapping('1001', 'mobile'));
    }
}
