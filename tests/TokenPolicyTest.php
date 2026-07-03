<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Claim\Scope;
use Kode\Jwt\Exception\TokenInvalidException;
use Kode\Jwt\Policy\TokenPolicy;
use Kode\Jwt\Token\Payload;
use PHPUnit\Framework\TestCase;

/**
 * TokenPolicy 策略对象单元测试
 *
 * 覆盖链式构造、enforce 校验、satisfies 判定、toArray 序列化。
 */
class TokenPolicyTest extends TestCase
{
    /**
     * 构造测试用 Payload
     */
    private function makePayload(array $overrides = []): Payload
    {
        $defaults = [
            'uid' => 123,
            'username' => 'alice',
            'platform' => 'web',
            'exp' => time() + 3600,
            'iat' => time(),
            'jti' => 'policy_jti_001',
            'iss' => 'https://auth.example.com',
            'aud' => 'my-client-id',
            'sub' => 'user-123',
            'custom' => ['scope' => 'openid profile', 'tenant' => 'acme'],
        ];
        return Payload::fromArray(array_merge($defaults, $overrides));
    }

    /**
     * 空策略：所有 Payload 通过
     */
    public function testEmptyPolicyAllowsAll(): void
    {
        $policy = TokenPolicy::create();
        $payload = $this->makePayload();

        $result = $policy->enforce($payload);
        self::assertSame($payload, $result);
    }

    /**
     * 链式 with* 返回新实例
     */
    public function testWithMethodsReturnNewInstance(): void
    {
        $policy = TokenPolicy::create();
        $newPolicy = $policy->withIssuer('https://auth.example.com');

        self::assertNotSame($policy, $newPolicy);
        self::assertNull($policy->expectedIssuer);
        self::assertSame('https://auth.example.com', $newPolicy->expectedIssuer);
    }

    /**
     * issuer 校验
     */
    public function testEnforceIssuer(): void
    {
        $policy = TokenPolicy::create()->withIssuer('https://auth.example.com');
        $payload = $this->makePayload();

        self::assertSame($payload, $policy->enforce($payload));
    }

    /**
     * issuer 不匹配抛出异常
     */
    public function testEnforceIssuerMismatchThrows(): void
    {
        $policy = TokenPolicy::create()->withIssuer('https://other.example.com');
        $this->expectException(TokenInvalidException::class);
        $policy->enforce($this->makePayload());
    }

    /**
     * audience 校验
     */
    public function testEnforceAudience(): void
    {
        $policy = TokenPolicy::create()->withAudience(['my-client-id', 'other-client']);
        $payload = $this->makePayload();

        self::assertSame($payload, $policy->enforce($payload));
    }

    /**
     * audience 不匹配抛出异常
     */
    public function testEnforceAudienceMismatchThrows(): void
    {
        $policy = TokenPolicy::create()->withAudience('unknown-client');
        $this->expectException(TokenInvalidException::class);
        $policy->enforce($this->makePayload());
    }

    /**
     * platform 校验
     */
    public function testEnforcePlatform(): void
    {
        $policy = TokenPolicy::create()->withPlatform('web');
        $payload = $this->makePayload();

        self::assertSame($payload, $policy->enforce($payload));
    }

    /**
     * platform 不匹配抛出异常
     */
    public function testEnforcePlatformMismatchThrows(): void
    {
        $policy = TokenPolicy::create()->withPlatform('app');
        $this->expectException(TokenInvalidException::class);
        $policy->enforce($this->makePayload());
    }

    /**
     * requiredScopes：全部命中通过
     */
    public function testEnforceRequiredScopesMatch(): void
    {
        $policy = TokenPolicy::create()->withRequiredScopes(['openid', 'profile']);
        $payload = $this->makePayload();
        self::assertSame($payload, $policy->enforce($payload));
    }

    /**
     * requiredScopes：缺失抛出异常
     */
    public function testEnforceRequiredScopesMissingThrows(): void
    {
        $policy = TokenPolicy::create()->withRequiredScopes(['openid', 'admin']);
        $this->expectException(TokenInvalidException::class);
        $policy->enforce($this->makePayload());
    }

    /**
     * anyScopes：命中其一通过
     */
    public function testEnforceAnyScopesMatch(): void
    {
        $policy = TokenPolicy::create()->withAnyScopes(['admin', 'profile']);
        $payload = $this->makePayload();
        self::assertSame($payload, $policy->enforce($payload));
    }

    /**
     * anyScopes：全部不命中抛出异常
     */
    public function testEnforceAnyScopesMissingThrows(): void
    {
        $policy = TokenPolicy::create()->withAnyScopes(['admin', 'write']);
        $this->expectException(TokenInvalidException::class);
        $policy->enforce($this->makePayload());
    }

    /**
     * requiredCustom：等值匹配通过
     */
    public function testEnforceRequiredCustomMatch(): void
    {
        $policy = TokenPolicy::create()->withRequiredCustom('tenant', 'acme');
        $payload = $this->makePayload();
        self::assertSame($payload, $policy->enforce($payload));
    }

    /**
     * requiredCustom：不匹配抛出异常
     */
    public function testEnforceRequiredCustomMismatchThrows(): void
    {
        $policy = TokenPolicy::create()->withRequiredCustom('tenant', 'other');
        $this->expectException(TokenInvalidException::class);
        $policy->enforce($this->makePayload());
    }

    /**
     * ignoreExpiration=true 时过期 Token 也能通过
     */
    public function testIgnoreExpirationAllowsExpiredToken(): void
    {
        $policy = TokenPolicy::create()->withIgnoreExpiration(true);
        $payload = $this->makePayload([
            'exp' => time() - 100,
            'iat' => time() - 200,
        ]);

        self::assertSame($payload, $policy->enforce($payload));
    }

    /**
     * satisfies 不抛异常
     */
    public function testSatisfiesReturnsFalseOnFailure(): void
    {
        $policy = TokenPolicy::create()->withIssuer('https://other.example.com');
        self::assertFalse($policy->satisfies($this->makePayload()));
    }

    /**
     * satisfies 通过返回 true
     */
    public function testSatisfiesReturnsTrueOnSuccess(): void
    {
        $policy = TokenPolicy::create()->withIssuer('https://auth.example.com');
        self::assertTrue($policy->satisfies($this->makePayload()));
    }

    /**
     * extractAllowedScope 返回命中 scope
     */
    public function testExtractAllowedScope(): void
    {
        $policy = TokenPolicy::create()->withRequiredScopes(['openid', 'admin']);
        $payload = $this->makePayload(); // scope = openid profile

        $scope = $policy->extractAllowedScope($payload);
        self::assertInstanceOf(Scope::class, $scope);
        self::assertTrue($scope->has('openid'));
        self::assertFalse($scope->has('profile'));
    }

    /**
     * toArray 序列化
     */
    public function testToArray(): void
    {
        $policy = TokenPolicy::create()
            ->withIssuer('https://auth.example.com')
            ->withAudience('my-client-id')
            ->withPlatform('web')
            ->withRequiredScopes(['openid'])
            ->withAnyScopes(['profile', 'email'])
            ->withRequiredCustom('tenant', 'acme')
            ->withClockSkew(60)
            ->withIgnoreExpiration(false);

        $array = $policy->toArray();

        self::assertSame('https://auth.example.com', $array['expected_issuer']);
        self::assertSame('my-client-id', $array['expected_audience']);
        self::assertSame('web', $array['expected_platform']);
        self::assertSame(['openid'], $array['required_scopes']);
        self::assertSame(['profile', 'email'], $array['any_scopes']);
        self::assertSame(['tenant' => 'acme'], $array['required_custom']);
        self::assertSame(60, $array['clock_skew']);
        self::assertFalse($array['ignore_expiration']);
    }

    /**
     * fromArray 反序列化
     */
    public function testFromArray(): void
    {
        $data = [
            'expected_issuer' => 'https://auth.example.com',
            'expected_audience' => 'my-client-id',
            'expected_platform' => 'web',
            'required_scopes' => ['openid'],
            'any_scopes' => ['profile'],
            'required_custom' => ['tenant' => 'acme'],
            'clock_skew' => 60,
            'ignore_expiration' => false,
        ];

        $policy = TokenPolicy::fromArray($data);

        self::assertSame('https://auth.example.com', $policy->expectedIssuer);
        self::assertSame('my-client-id', $policy->expectedAudience);
        self::assertSame('web', $policy->expectedPlatform);
        self::assertSame(['openid'], $policy->requiredScopes);
        self::assertSame(['profile'], $policy->anyScopes);
        self::assertSame(['tenant' => 'acme'], $policy->requiredCustom);
        self::assertSame(60, $policy->clockSkew);
        self::assertFalse($policy->ignoreExpiration);
    }

    /**
     * 综合策略链
     */
    public function testComplexPolicyChain(): void
    {
        $payload = $this->makePayload();
        $policy = TokenPolicy::create()
            ->withIssuer('https://auth.example.com')
            ->withAudience('my-client-id')
            ->withPlatform('web')
            ->withRequiredScopes(['openid'])
            ->withAnyScopes(['profile', 'email'])
            ->withRequiredCustom('tenant', 'acme')
            ->withClockSkew(60);

        $result = $policy->enforce($payload);
        self::assertSame($payload, $result);
    }
}
