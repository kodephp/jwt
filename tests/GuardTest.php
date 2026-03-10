<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Config\ConfigLoader;
use Kode\Jwt\Contract\TokenManagerInterface;
use Kode\Jwt\Event\EventDispatcher;
use Kode\Jwt\Exception\TokenBlacklistedException;
use Kode\Jwt\Guard\MloGuard;
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
}
