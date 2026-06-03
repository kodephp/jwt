<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Exception\TokenInvalidException;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Parser;
use Kode\Jwt\Token\Payload;
use PHPUnit\Framework\TestCase;

/**
 * Parser 业务声明（expected_claims）校验测试
 */
final class ParserExpectedClaimsTest extends TestCase
{
    private const SECRET = 'unit_test_secret_unit_test_secret';

    private function buildConfig(array $extra = []): array
    {
        return array_merge([
            'algo' => 'HS256',
            'secret' => self::SECRET,
            'ttl' => 60,
        ], $extra);
    }

    private function makeToken(array $extra = []): string
    {
        $now = time();
        $payload = new Payload(
            uid: 1,
            platform: 'web',
            exp: $now + 60,
            iat: $now,
            jti: 'jti_test',
            nonce: $extra['nonce'] ?? null,
            audience: $extra['audience'] ?? null,
            issuer: $extra['issuer'] ?? null,
            subject: $extra['subject'] ?? null,
            custom: $extra['custom'] ?? []
        );

        $builder = (new Builder($this->buildConfig()))
            ->fromPayload($payload)
            ->setId('jti_test')
            ->setIssuedAt($now)
            ->setExpiration($now + 60);

        // 显式设置 iss/aud/sub（标准 JWT 声明键名）
        if (isset($extra['issuer'])) {
            $builder->setIssuer($extra['issuer']);
        }
        if (isset($extra['audience'])) {
            $builder->setAudience($extra['audience']);
        }
        if (isset($extra['subject'])) {
            $builder->setSubject($extra['subject']);
        }
        if (isset($extra['custom'])) {
            $builder->setCustom($extra['custom']);
        }
        if (isset($extra['nonce'])) {
            $builder->setNonce($extra['nonce']);
        }

        return $builder->build();
    }

    public function testParsePassesWhenNoExpectedClaims(): void
    {
        $token = $this->makeToken(['issuer' => 'auth.example.com']);
        $parser = new Parser($this->buildConfig());
        $payload = $parser->parse($token);
        self::assertSame('auth.example.com', $payload->getIssuer());
    }

    public function testParseRejectsMismatchedIssuer(): void
    {
        $token = $this->makeToken(['issuer' => 'attacker.example.com']);
        $parser = new Parser($this->buildConfig());

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Issuer mismatch');
        $parser->parse($token, null, false, ['iss' => 'auth.example.com']);
    }

    public function testParseAcceptsMatchingIssuer(): void
    {
        $token = $this->makeToken(['issuer' => 'auth.example.com']);
        $parser = new Parser($this->buildConfig());
        $payload = $parser->parse($token, null, false, ['iss' => 'auth.example.com']);
        self::assertSame('auth.example.com', $payload->getIssuer());
    }

    public function testParseAudienceIntersection(): void
    {
        $token = $this->makeToken(['audience' => ['api', 'mobile']]);
        $parser = new Parser($this->buildConfig());

        // 至少命中其一即可通过
        $payload = $parser->parse($token, null, false, ['aud' => ['webhook', 'mobile']]);
        self::assertSame(['api', 'mobile'], $payload->getAudience());
    }

    public function testParseRejectsNonIntersectingAudience(): void
    {
        $token = $this->makeToken(['audience' => 'api']);
        $parser = new Parser($this->buildConfig());

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Audience mismatch');
        $parser->parse($token, null, false, ['aud' => 'mobile']);
    }

    public function testParseSubjectMatch(): void
    {
        $token = $this->makeToken(['subject' => 'auth-service']);
        $parser = new Parser($this->buildConfig());

        $payload = $parser->parse($token, null, false, ['sub' => 'auth-service']);
        self::assertSame('auth-service', $payload->getSubject());

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Subject mismatch');
        $parser->parse($token, null, false, ['sub' => 'payment-service']);
    }

    public function testParseCustomClaimExactMatch(): void
    {
        $now = time();
        $builder = (new Builder($this->buildConfig()))
            ->setUid(1)
            ->setPlatform('web')
            ->setId('jti_test')
            ->setIssuedAt($now)
            ->setExpiration($now + 60)
            ->setClaim('tenant_id', 't_1');
        $token = $builder->build();

        $parser = new Parser($this->buildConfig());

        // 不匹配时报错
        $threwException = false;
        try {
            $parser->parse($token, null, false, ['tenant_id' => 't_2']);
        } catch (TokenInvalidException $e) {
            $threwException = true;
            self::assertStringContainsString('Claim mismatch', $e->getMessage());
        }
        self::assertTrue($threwException, '应抛出 TokenInvalidException');

        // 匹配时通过
        $parser->parse($token, null, false, ['tenant_id' => 't_1']);
        self::assertTrue(true);
    }
}
