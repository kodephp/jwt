<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Claim\Confirmation;
use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Key\JwkFactory;
use PHPUnit\Framework\TestCase;

/**
 * cnf 确认声明（RFC 7800）单元测试
 */
final class ConfirmationTest extends TestCase
{
    public function testWithJkt(): void
    {
        $cnf = Confirmation::withJkt('abc123');
        self::assertSame('abc123', $cnf->jkt);
        self::assertSame(['jkt' => 'abc123'], $cnf->toArray());
    }

    public function testWithJwkComputesJkt(): void
    {
        $pair = JwkFactory::generateEcKeyPair('P-256');
        $cnf = Confirmation::withJwk($pair['private']);

        self::assertNotNull($cnf->jkt);
        // jkt 必须匹配公钥 JWK 的 RFC 7638 指纹
        self::assertSame($pair['public']->thumbprint('sha256'), $cnf->jkt);
        // jwk 必须是公钥（绝不泄露 d）
        self::assertFalse($cnf->jwk->isPrivate());
        self::assertSame($cnf->jkt, $cnf->toArray()['jkt']);
    }

    public function testWithJku(): void
    {
        $cnf = Confirmation::withJku('https://issuer.example.com/jwks', 'key-1');
        self::assertSame('https://issuer.example.com/jwks', $cnf->jku);
        self::assertSame('key-1', $cnf->kid);
        self::assertSame([
            'jku' => 'https://issuer.example.com/jwks',
            'kid' => 'key-1',
        ], $cnf->toArray());
    }

    public function testToJson(): void
    {
        $cnf = Confirmation::withJkt('abc');
        self::assertJson($cnf->toJson());
        self::assertStringContainsString('"jkt":"abc"', $cnf->toJson());
    }

    public function testEmptyThrows(): void
    {
        $this->expectException(JwtException::class);
        new Confirmation();
    }
}
