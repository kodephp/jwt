<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Token\Payload;
use PHPUnit\Framework\TestCase;

/**
 * Payload 新增声明（nonce/iss/aud/sub）测试
 */
final class PayloadClaimsTest extends TestCase
{
    public function testDefaultConstructorIsBackwardCompatible(): void
    {
        $now = time();
        $payload = new Payload(
            uid: 1,
            platform: 'web',
            exp: $now + 3600,
            iat: $now,
            jti: 'jti_a'
        );

        self::assertNull($payload->getNonce());
        self::assertNull($payload->getAudience());
        self::assertNull($payload->getIssuer());
        self::assertNull($payload->getSubject());
    }

    public function testNewClaimsAreStored(): void
    {
        $now = time();
        $payload = new Payload(
            uid: 1,
            platform: 'web',
            exp: $now + 3600,
            iat: $now,
            jti: 'jti_b',
            nonce: 'abc123',
            audience: ['api.example.com', 'mobile'],
            issuer: 'https://auth.example.com',
            subject: 'user-service'
        );

        self::assertSame('abc123', $payload->getNonce());
        self::assertSame(['api.example.com', 'mobile'], $payload->getAudience());
        self::assertSame('https://auth.example.com', $payload->getIssuer());
        self::assertSame('user-service', $payload->getSubject());
    }

    public function testFromArrayParsesShortAndLongKeys(): void
    {
        $now = time();
        $data = [
            'platform' => 'web',
            'exp' => $now + 3600,
            'iat' => $now,
            'jti' => 'jti_c',
            'nonce' => 'nonce_xyz',
            'iss' => 'auth.example.com',
            'aud' => 'api',
            'sub' => 'main',
        ];

        $payload = Payload::fromArray($data);
        self::assertSame('nonce_xyz', $payload->getNonce());
        self::assertSame('auth.example.com', $payload->getIssuer());
        self::assertSame('api', $payload->getAudience());
        self::assertSame('main', $payload->getSubject());
    }

    public function testFromArrayAcceptsAliasKeys(): void
    {
        $now = time();
        $data = [
            'platform' => 'app',
            'exp' => $now + 3600,
            'iat' => $now,
            'jti' => 'jti_d',
            'audience' => 'mobile-app',
            'issuer' => 'https://issuer',
            'subject' => 'auth',
        ];

        $payload = Payload::fromArray($data);
        self::assertSame('mobile-app', $payload->getAudience());
        self::assertSame('https://issuer', $payload->getIssuer());
        self::assertSame('auth', $payload->getSubject());
    }

    public function testGenerateJtiIsHighEntropy(): void
    {
        $jti1 = Payload::generateJti();
        $jti2 = Payload::generateJti();

        self::assertNotSame($jti1, $jti2);
        self::assertStringStartsWith('jwt_', $jti1);
        // 4 ('jwt_') + 32 (hex 字符) = 36
        self::assertSame(36, strlen($jti1));
        self::assertMatchesRegularExpression('/^jwt_[a-f0-9]{32}$/', $jti1);
    }

    public function testQuickCreateAcceptsNewKeys(): void
    {
        $payload = Payload::quickCreate([
            'uid' => 7,
            'platform' => 'app',
            'nonce' => 'n_quick',
            'aud' => 'api',
            'iss' => 'auth',
        ], ['ttl' => 60]);

        self::assertSame('n_quick', $payload->getNonce());
        self::assertSame('api', $payload->getAudience());
        self::assertSame('auth', $payload->getIssuer());
        self::assertNotEmpty($payload->jti);
    }
}
