<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Enum\Algorithm;
use PHPUnit\Framework\TestCase;

final class AlgorithmTest extends TestCase
{
    public function testHmacAlgorithms(): void
    {
        self::assertTrue(Algorithm::HS256->isHmac());
        self::assertTrue(Algorithm::HS384->isHmac());
        self::assertTrue(Algorithm::HS512->isHmac());

        self::assertFalse(Algorithm::RS256->isHmac());
        self::assertFalse(Algorithm::ES256->isHmac());
        self::assertFalse(Algorithm::PS256->isHmac());
    }

    public function testRsaAlgorithms(): void
    {
        self::assertTrue(Algorithm::RS256->isRsa());
        self::assertTrue(Algorithm::RS384->isRsa());
        self::assertTrue(Algorithm::RS512->isRsa());

        self::assertFalse(Algorithm::HS256->isRsa());
        self::assertFalse(Algorithm::ES256->isRsa());
    }

    public function testEcdsaAlgorithms(): void
    {
        self::assertTrue(Algorithm::ES256->isEcdsa());
        self::assertTrue(Algorithm::ES384->isEcdsa());
        self::assertTrue(Algorithm::ES512->isEcdsa());

        self::assertFalse(Algorithm::HS256->isEcdsa());
        self::assertFalse(Algorithm::RS256->isEcdsa());
    }

    public function testAsymmetricAlgorithms(): void
    {
        self::assertTrue(Algorithm::RS256->isAsymmetric());
        self::assertTrue(Algorithm::ES256->isAsymmetric());
        self::assertTrue(Algorithm::PS256->isAsymmetric());

        self::assertFalse(Algorithm::HS256->isAsymmetric());
    }

    public function testGetKeyBits(): void
    {
        self::assertSame(256, Algorithm::HS256->getKeyBits());
        self::assertSame(256, Algorithm::RS256->getKeyBits());
        self::assertSame(256, Algorithm::ES256->getKeyBits());
        self::assertSame(256, Algorithm::PS256->getKeyBits());

        self::assertSame(384, Algorithm::HS384->getKeyBits());
        self::assertSame(512, Algorithm::HS512->getKeyBits());
    }

    public function testValues(): void
    {
        $values = Algorithm::values();

        self::assertContains('HS256', $values);
        self::assertContains('RS256', $values);
        self::assertContains('ES256', $values);
        self::assertContains('PS256', $values);
        self::assertContains('EdDSA', $values);
        self::assertCount(13, $values);
    }

    public function testHmacAlgorithmsList(): void
    {
        $hmacAlgos = Algorithm::hmacAlgorithms();

        self::assertCount(3, $hmacAlgos);
        self::assertSame(Algorithm::HS256, $hmacAlgos[0]);
        self::assertSame(Algorithm::HS384, $hmacAlgos[1]);
        self::assertSame(Algorithm::HS512, $hmacAlgos[2]);
    }

    public function testAsymmetricAlgorithmsList(): void
    {
        $asymmetricAlgos = Algorithm::asymmetricAlgorithms();

        self::assertCount(10, $asymmetricAlgos);
    }
}
