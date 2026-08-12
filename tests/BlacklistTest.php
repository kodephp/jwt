<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\KodeJwt;
use Kode\Jwt\Storage\MemoryStorage;
use Kode\Jwt\Storage\NullStorage;
use Kode\Jwt\Token\Builder;
use PHPUnit\Framework\TestCase;

/**
 * 黑名单完整生命周期测试：
 *  - 按 Token 撤销（revokeToken）→ introspect / isTokenValid 立即失效
 *  - 按 jti 撤销（revokeJti）→ isBlacklisted
 *  - 撤销恢复（unblacklist）→ 再次生效
 *  - removeFromBlacklist 在存储后端的行为
 */
final class BlacklistTest extends TestCase
{
    private function buildToken(string $jti, string $secret = 'bl_secret'): string
    {
        $builder = new Builder([
            'secret' => $secret,
            'algo' => 'HS256',
            'platform' => 'web',
        ]);
        $builder->setSubject('user-1')
            ->setExpiration(time() + 3600)
            ->setPlatform('web')
            ->setId($jti);

        return $builder->build();
    }

    protected function setUp(): void
    {
        KodeJwt::init([
            'defaults' => ['guard' => 'api', 'storage' => 'memory'],
            'guards' => ['api' => [
                'driver' => 'sso',
                'storage' => 'memory',
                'algo' => 'HS256',
                'secret' => 'bl_secret',
                'ttl' => 3600,
            ]],
        ]);
    }

    public function testRevokeTokenInvalidatesIntrospectAndIsValid(): void
    {
        $token = $this->buildToken('jti-revoke-full');

        // 撤销前有效
        self::assertTrue(KodeJwt::isTokenValid($token));
        self::assertTrue(KodeJwt::introspect($token)->active);

        // 按完整 Token 撤销
        self::assertTrue(KodeJwt::revokeToken($token));
        self::assertTrue(KodeJwt::isBlacklisted('jti-revoke-full'));

        // 撤销后立即失效（introspect 与 isTokenValid 都应判定失效）
        self::assertFalse(KodeJwt::isTokenValid($token));
        self::assertFalse(KodeJwt::introspect($token)->active);
    }

    public function testRevokeJtiAndIsBlacklisted(): void
    {
        // 直接按 jti 撤销，无需持有原始 Token
        self::assertFalse(KodeJwt::isBlacklisted('jti-direct'));
        self::assertTrue(KodeJwt::revokeJti('jti-direct', 1800));
        self::assertTrue(KodeJwt::isBlacklisted('jti-direct'));
    }

    public function testUnblacklistRestoresValidity(): void
    {
        $token = $this->buildToken('jti-restore');
        self::assertTrue(KodeJwt::revokeToken($token));
        self::assertFalse(KodeJwt::isTokenValid($token));

        // 撤销恢复
        self::assertTrue(KodeJwt::unblacklist('jti-restore'));
        self::assertFalse(KodeJwt::isBlacklisted('jti-restore'));

        // 恢复后 Token 重新生效
        self::assertTrue(KodeJwt::isTokenValid($token));
        self::assertTrue(KodeJwt::introspect($token)->active);
    }

    public function testRemoveFromBlacklistOnMemoryStorage(): void
    {
        $storage = new MemoryStorage();
        self::assertFalse($storage->isBlacklisted('jti-mem'));
        self::assertTrue($storage->blacklist('jti-mem', 3600));
        self::assertTrue($storage->isBlacklisted('jti-mem'));

        // 移除（即便 jti 不在黑名单也返回 true）
        self::assertTrue($storage->removeFromBlacklist('jti-mem'));
        self::assertFalse($storage->isBlacklisted('jti-mem'));
        self::assertTrue($storage->removeFromBlacklist('never-existed'));
    }

    public function testRemoveFromBlacklistOnNullStorage(): void
    {
        $storage = new NullStorage();
        // 始终不命中黑名单，移除为安全空操作
        self::assertFalse($storage->isBlacklisted('jti-null'));
        self::assertTrue($storage->removeFromBlacklist('jti-null'));
    }
}
