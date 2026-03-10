<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Token\Payload;
use PHPUnit\Framework\TestCase;

final class PayloadTest extends TestCase
{
    public function testConstructValidPayload(): void
    {
        $now = time();

        $payload = new Payload(
            uid: 1,
            username: 'john',
            platform: 'web',
            exp: $now + 3600,
            iat: $now,
            jti: 'jti_1'
        );

        self::assertSame(1, $payload->uid);
        self::assertSame('john', $payload->username);
        self::assertSame('web', $payload->platform);
        self::assertSame('jti_1', $payload->jti);
    }

    public function testConstructMissingRequiredDataThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Payload(uid: 1);
    }

    public function testCreateMissingRequiredDataThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Payload::create(uid: 1);
    }

    public function testFromArrayMissingFieldsThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Payload::fromArray(['uid' => 1]);
    }
}
