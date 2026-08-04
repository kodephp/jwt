<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\KodeJwt;
use Kode\Jwt\OAuth2\RevocationHandler;
use Kode\Jwt\OAuth2\RevocationResponse;
use Kode\Jwt\Storage\MemoryStorage;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Parser;
use PHPUnit\Framework\TestCase;

/**
 * Token 撤销端点（RFC 7009）单元测试
 */
final class RevocationTest extends TestCase
{
    private function buildToken(string $secret = 'revoke_secret', string $platform = 'web'): string
    {
        $builder = new Builder([
            'secret' => $secret,
            'algo' => 'HS256',
            'platform' => $platform,
        ]);
        $builder->setSubject('user-1')
            ->setExpiration(time() + 3600)
            ->setPlatform($platform)
            ->setId('jti-to-revoke');

        return $builder->build();
    }

    public function testRevokeBlacklistsJti(): void
    {
        $token = $this->buildToken();
        $storage = new MemoryStorage();
        $parser = new Parser(['secret' => 'revoke_secret', 'algo' => 'HS256']);
        $handler = new RevocationHandler($parser, $storage);

        $resp = $handler->revoke($token);
        self::assertTrue($resp->isRevoked());
        self::assertSame(200, $resp->httpStatus());

        // jti 已入黑名单
        self::assertTrue($storage->isBlacklisted('jti-to-revoke'));
    }

    public function testRevokeGarbageTokenReturnsSuccess(): void
    {
        $storage = new MemoryStorage();
        $parser = new Parser(['secret' => 'revoke_secret', 'algo' => 'HS256']);
        $handler = new RevocationHandler($parser, $storage);

        // 无效 token 不抛异常，按 RFC 7009 视为已撤销（侧通道防护）
        $resp = $handler->revoke('not-a-real-token');
        self::assertTrue($resp->isRevoked());
        self::assertSame(200, $resp->httpStatus());
    }

    public function testRevocationResponseError(): void
    {
        $resp = RevocationResponse::error('unsupported_token_type', 'msg');
        self::assertFalse($resp->isRevoked());
        self::assertSame(400, $resp->httpStatus());
        self::assertSame([
            'error' => 'unsupported_token_type',
            'error_description' => 'msg',
        ], $resp->toArray());
    }

    public function testSuccessResponseEmptyBody(): void
    {
        self::assertSame([], RevocationResponse::success()->toArray());
    }

    public function testFacadeRevocation(): void
    {
        KodeJwt::init([
            'defaults' => ['guard' => 'api', 'storage' => 'memory'],
            'guards' => ['api' => [
                'driver' => 'sso',
                'storage' => 'memory',
                'algo' => 'HS256',
                'secret' => 'revoke_secret',
                'ttl' => 3600,
            ]],
        ]);

        $token = $this->buildToken();
        $resp = KodeJwt::revocation()->revoke($token);
        self::assertTrue($resp->isRevoked());
    }
}
