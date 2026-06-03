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

    /**
     * 验证 setEncryptedData 在 readonly 模式下返回新实例
     */
    public function testSetEncryptedDataReturnsNewInstance(): void
    {
        $now = time();
        $original = new Payload(
            uid: 1,
            platform: 'web',
            exp: $now + 3600,
            iat: $now,
            jti: 'jti_setenc'
        );

        $updated = $original->setEncryptedData('enc_blob');

        // 原实例不被修改（immutable）
        self::assertFalse($original->hasEncryptedData());
        // 新实例携带加密数据
        self::assertTrue($updated->hasEncryptedData());
        self::assertSame('enc_blob', $updated->getEncryptedData());
        // 其他字段保持一致
        self::assertSame($original->jti, $updated->jti);
        self::assertSame($original->uid, $updated->uid);
    }

    /**
     * 验证 toArray 将 issuer/audience/subject 映射为标准声明键
     */
    public function testToArrayMapsStandardClaims(): void
    {
        $now = time();
        $payload = new Payload(
            uid: 1,
            platform: 'web',
            exp: $now + 3600,
            iat: $now,
            jti: 'jti_std',
            audience: ['api.example.com'],
            issuer: 'https://auth.example.com',
            subject: 'auth-service',
        );

        $array = $payload->toArray();
        self::assertArrayHasKey('iss', $array);
        self::assertArrayHasKey('aud', $array);
        self::assertArrayHasKey('sub', $array);
        self::assertArrayNotHasKey('issuer', $array);
        self::assertArrayNotHasKey('audience', $array);
        self::assertArrayNotHasKey('subject', $array);
        self::assertSame('https://auth.example.com', $array['iss']);
        self::assertSame(['api.example.com'], $array['aud']);
        self::assertSame('auth-service', $array['sub']);
    }
}
