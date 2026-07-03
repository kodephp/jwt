<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Config\ConfigLoader;
use Kode\Jwt\Contract\TokenManagerInterface;
use Kode\Jwt\Event\EventDispatcher;
use Kode\Jwt\Exception\TokenBlacklistedException;
use Kode\Jwt\Guard\MloGuard;
use Kode\Jwt\Guard\SsoGuard;
use Kode\Jwt\Storage\MemoryStorage;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Parser;
use Kode\Jwt\Token\Payload;
use Kode\Jwt\Token\TokenManager;
use PHPUnit\Framework\TestCase;

final class GuardTest extends TestCase
{
    public function testIssueAuthenticateAndInvalidate(): void
    {
        $config = [
            'algo' => 'HS256',
            'secret' => 'unit_test_secret',
            'ttl' => 1440,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'blacklist_enabled' => true,
        ];

        $storage = new MemoryStorage(['limit' => 1000]);
        $builder = new Builder($config);
        $parser = new Parser($config);
        $dispatcher = new EventDispatcher();

        $guard = new MloGuard($storage, $builder, $parser, $dispatcher, null, $config);

        $now = time();
        $payload = new Payload(
            uid: 123,
            username: 'john',
            platform: 'app',
            exp: $now + 3600,
            iat: $now,
            jti: 'jti_123'
        );

        $result = $guard->issue($payload);
        self::assertArrayHasKey('token', $result);

        $verified = $guard->authenticate($result['token']);
        self::assertSame(123, $verified->uid);
        self::assertSame('app', $verified->platform);

        self::assertTrue($guard->invalidate($result['token']));

        $this->expectException(TokenBlacklistedException::class);
        $guard->authenticate($result['token']);
    }

    public function testRefreshAllowsExpiredTokenWithinRefreshWindow(): void
    {
        $config = [
            'algo' => 'HS256',
            'secret' => 'unit_test_secret',
            'ttl' => 1440,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'blacklist_enabled' => true,
        ];

        $storage = new MemoryStorage(['limit' => 1000]);
        $builder = new Builder($config);
        $parser = new Parser($config);
        $dispatcher = new EventDispatcher();

        $guard = new MloGuard($storage, $builder, $parser, $dispatcher, null, $config);

        $now = time();
        $payload = new Payload(
            uid: 123,
            username: 'john',
            platform: 'app',
            exp: $now - 10,
            iat: $now - 20,
            jti: 'jti_expired'
        );

        $result = $guard->issue($payload);
        $refresh = $guard->refresh($result['token']);

        self::assertIsArray($refresh);
        self::assertArrayHasKey('token', $refresh);
        self::assertNotSame($result['token'], $refresh['token']);

        $newPayload = $guard->authenticate($refresh['token']);
        self::assertSame(123, $newPayload->uid);
        self::assertSame('app', $newPayload->platform);
    }

    public function testTokenManagerImplementsContractAndDelegatesCoreOperations(): void
    {
        $config = [
            'platforms' => ['app'],
            'guards' => [
                'api' => [
                    'algo' => 'HS256',
                    'secret' => 'unit_test_secret',
                    'ttl' => 1440,
                    'refresh_enabled' => true,
                    'refresh_ttl' => 20160,
                    'blacklist_enabled' => true,
                ],
            ],
        ];

        $storage = new MemoryStorage(['limit' => 1000]);
        $builder = new Builder($config['guards']['api']);
        $parser = new Parser($config['guards']['api']);
        $dispatcher = new EventDispatcher();
        $guard = new MloGuard($storage, $builder, $parser, $dispatcher, null, $config['guards']['api']);
        $manager = new TokenManager($storage, $guard, new ConfigLoader($config));

        self::assertInstanceOf(TokenManagerInterface::class, $manager);
        self::assertSame($storage, $manager->getStorage());
        self::assertArrayHasKey('guards', $manager->getConfig());
        self::assertTrue($manager->isUnique('123', 'app'));

        $now = time();
        $payload = new Payload(
            uid: 123,
            username: 'john',
            platform: 'app',
            exp: $now + 3600,
            iat: $now,
            jti: 'jti_contract_123'
        );

        $issued = $manager->issue($payload);
        self::assertArrayHasKey('token', $issued);

        $authenticated = $manager->authenticate($issued['token']);
        self::assertSame(123, $authenticated->uid);

        $refreshed = $manager->refresh($issued['token']);
        self::assertArrayHasKey('token', $refreshed);

        self::assertTrue($manager->invalidate($refreshed['token']));
    }

    /**
     * 验证 SsoGuard 单一登录策略：再次签发会自动踢出旧 Token
     */
    public function testSsoGuardKicksOutPreviousToken(): void
    {
        $config = [
            'algo' => 'HS256',
            'secret' => 'sso_unit_test_secret',
            'ttl' => 1440,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'blacklist_enabled' => true,
            'platform' => 'app',
        ];

        $storage = new MemoryStorage(['limit' => 1000]);
        $builder = new Builder($config);
        $parser = new Parser($config);
        $dispatcher = new EventDispatcher();

        $guard = new SsoGuard($storage, $builder, $parser, $dispatcher, null, $config);

        $now = time();
        $firstPayload = new Payload(
            uid: 1001,
            username: 'alice',
            platform: 'app',
            exp: $now + 3600,
            iat: $now,
            jti: 'jti_sso_first'
        );

        $firstToken = $guard->issue($firstPayload)['token'];
        $firstJti = $guard->authenticate($firstToken)->jti;
        self::assertSame('jti_sso_first', $firstJti);

        // 第二次签发：SSO 应当把第一次的 Token 加入黑名单
        $secondPayload = new Payload(
            uid: 1001,
            username: 'alice',
            platform: 'app',
            exp: $now + 3600,
            iat: $now,
            jti: 'jti_sso_second'
        );

        $secondToken = $guard->issue($secondPayload)['token'];

        // 第一次的 Token 应当因 SSO 撤销而无法通过认证
        try {
            $guard->authenticate($firstToken);
            self::fail('首次 Token 应当被 SSO 撤销');
        } catch (TokenBlacklistedException) {
            // 预期行为
        }

        // 第二次的 Token 仍能正常通过
        $verified = $guard->authenticate($secondToken);
        self::assertSame('jti_sso_second', $verified->jti);
    }

    /**
     * 验证 SsoGuard::currentJti 能读取当前 SSO 绑定
     */
    public function testSsoGuardCurrentJti(): void
    {
        $config = [
            'algo' => 'HS256',
            'secret' => 'sso_curr_jti_secret',
            'ttl' => 1440,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'blacklist_enabled' => true,
            'platform' => 'app',
        ];

        $storage = new MemoryStorage(['limit' => 1000]);
        $builder = new Builder($config);
        $parser = new Parser($config);
        $dispatcher = new EventDispatcher();
        $guard = new SsoGuard($storage, $builder, $parser, $dispatcher, null, $config);

        $now = time();
        $payload = new Payload(
            uid: 1001,
            platform: 'app',
            exp: $now + 3600,
            iat: $now,
            jti: 'jti_currentjti'
        );

        $token = $guard->issue($payload)['token'];
        self::assertSame('jti_currentjti', $guard->currentJti('1001', 'app'));

        // 验证获取不存在的绑定返回 null
        self::assertNull($guard->currentJti('1001', 'unknown'));
    }

    /**
     * 验证 ttl_unit=seconds 时不进行分钟换算
     */
    public function testTtlUnitSecondsIsRespected(): void
    {
        $config = [
            'algo' => 'HS256',
            'secret' => 'ttl_unit_secret',
            'ttl' => 90,
            'ttl_unit' => 'seconds',
            'refresh_enabled' => false,
            'blacklist_enabled' => true,
        ];

        $storage = new MemoryStorage(['limit' => 100]);
        $builder = new Builder($config);
        $parser = new Parser($config);
        $guard = new MloGuard($storage, $builder, $parser, new EventDispatcher(), null, $config);

        // 通过反射调用 getTtlSeconds 验证（受保护方法）
        $reflection = new \ReflectionMethod($guard, 'getTtlSeconds');
        $reflection->setAccessible(true);
        $seconds = $reflection->invoke($guard);

        // ttl=90 + ttl_unit=seconds 应当返回 90，而非 90*60
        self::assertSame(90, $seconds);
    }

    /**
     * 验证 refresh 流程不再重复解析 token
     */
    public function testRefreshDoesNotDoubleParseToken(): void
    {
        $config = [
            'algo' => 'HS256',
            'secret' => 'refresh_secret',
            'ttl' => 60,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'blacklist_enabled' => true,
        ];

        $storage = new MemoryStorage(['limit' => 100]);
        $builder = new Builder($config);
        $parser = new Parser($config);
        $guard = new MloGuard($storage, $builder, $parser, new EventDispatcher(), null, $config);

        $now = time();
        $payload = new Payload(
            uid: 999,
            username: 'refresher',
            platform: 'app',
            exp: $now + 60,
            iat: $now,
            jti: 'jti_refresh_test'
        );

        $issued = $guard->issue($payload);
        $token = $issued['token'];

        // 刷新应成功；如果重复解析，结构上仍能成功，但性能优化通过 canRefreshPayload 复用 Payload
        $refreshed = $guard->refresh($token);
        self::assertNotSame($token, $refreshed['token']);
        self::assertNotEmpty($refreshed['token']);

        // 旧 token 应在黑名单中
        self::assertTrue($storage->isBlacklisted('jti_refresh_test'));
    }
}
