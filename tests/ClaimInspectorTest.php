<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Claim\ClaimInspector;
use Kode\Jwt\Claim\Scope;
use Kode\Jwt\Exception\TokenInvalidException;
use Kode\Jwt\Token\Payload;
use PHPUnit\Framework\TestCase;

/**
 * ClaimInspector 单元测试
 *
 * 覆盖 issuer / audience / subject / time window / scope / custom 校验。
 */
class ClaimInspectorTest extends TestCase
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
            'jti' => 'test_jti_001',
            'issuer' => 'https://auth.example.com',
            'audience' => 'my-client-id',
            'subject' => 'user-123',
            'custom' => ['scope' => 'openid profile', 'tenant' => 'acme'],
        ];
        $data = array_merge($defaults, $overrides);
        return Payload::fromArray($data);
    }

    /**
     * issuer 匹配
     */
    public function testAssertIssuerMatch(): void
    {
        $payload = $this->makePayload();
        $inspector = new ClaimInspector();

        $result = $inspector->assertIssuer($payload, 'https://auth.example.com');
        self::assertSame($inspector, $result);
    }

    /**
     * issuer 不匹配抛出异常
     */
    public function testAssertIssuerMismatch(): void
    {
        $payload = $this->makePayload();
        $this->expectException(TokenInvalidException::class);
        (new ClaimInspector())->assertIssuer($payload, 'https://other.example.com');
    }

    /**
     * audience 命中
     */
    public function testAssertAudienceMatch(): void
    {
        $payload = $this->makePayload();
        (new ClaimInspector())->assertAudience($payload, 'my-client-id');
        $this->expectNotToPerformAssertions();
    }

    /**
     * audience 数组形式匹配
     */
    public function testAssertAudienceArrayMatch(): void
    {
        $payload = $this->makePayload(['audience' => ['client-a', 'client-b']]);
        (new ClaimInspector())->assertAudience($payload, ['client-b', 'client-c']);
        $this->expectNotToPerformAssertions();
    }

    /**
     * audience 不命中
     */
    public function testAssertAudienceMismatch(): void
    {
        $payload = $this->makePayload();
        $this->expectException(TokenInvalidException::class);
        (new ClaimInspector())->assertAudience($payload, 'unknown-client');
    }

    /**
     * audience 缺失
     */
    public function testAssertAudienceMissing(): void
    {
        $payload = $this->makePayload(['audience' => null]);
        $this->expectException(TokenInvalidException::class);
        (new ClaimInspector())->assertAudience($payload, 'my-client-id');
    }

    /**
     * subject 缺失
     */
    public function testAssertSubjectMissing(): void
    {
        $payload = $this->makePayload(['subject' => null]);
        $this->expectException(TokenInvalidException::class);
        (new ClaimInspector())->assertSubject($payload);
    }

    /**
     * subject 严格匹配
     */
    public function testAssertSubjectMatch(): void
    {
        $payload = $this->makePayload();
        (new ClaimInspector())->assertSubject($payload, 'user-123');
        $this->expectNotToPerformAssertions();
    }

    /**
     * 时间窗口：未来 iat 抛出异常
     */
    public function testAssertTimeWindowFutureIatThrows(): void
    {
        $payload = $this->makePayload(['iat' => time() + 600, 'exp' => time() + 7200]);
        $this->expectException(TokenInvalidException::class);
        (new ClaimInspector())->assertTimeWindow($payload, 30);
    }

    /**
     * 时间窗口：已过期
     */
    public function testAssertTimeWindowExpiredThrows(): void
    {
        $payload = $this->makePayload(['exp' => time() - 100, 'iat' => time() - 200]);
        $this->expectException(TokenInvalidException::class);
        (new ClaimInspector())->assertTimeWindow($payload, 30);
    }

    /**
     * 时间窗口：忽略过期可绕过 exp 校验
     */
    public function testAssertTimeWindowIgnoreExpiration(): void
    {
        $payload = $this->makePayload(['exp' => time() - 100, 'iat' => time() - 200]);
        (new ClaimInspector())->assertTimeWindow($payload, 30, true);
        $this->expectNotToPerformAssertions();
    }

    /**
     * scope 全部命中
     */
    public function testAssertScopesAllMatch(): void
    {
        $payload = $this->makePayload();
        (new ClaimInspector())->assertScopesAll($payload, ['openid', 'profile']);
        $this->expectNotToPerformAssertions();
    }

    /**
     * scope 缺失
     */
    public function testAssertScopesAllMissing(): void
    {
        $payload = $this->makePayload();
        $this->expectException(TokenInvalidException::class);
        (new ClaimInspector())->assertScopesAll($payload, ['openid', 'admin']);
    }

    /**
     * scope 任一命中
     */
    public function testAssertScopesAnyMatch(): void
    {
        $payload = $this->makePayload();
        (new ClaimInspector())->assertScopesAny($payload, ['admin', 'profile']);
        $this->expectNotToPerformAssertions();
    }

    /**
     * scope 数组形式
     */
    public function testExtractScopeFromArray(): void
    {
        $payload = $this->makePayload(['custom' => ['scope' => ['openid', 'email']]]);
        $scope = (new ClaimInspector())->extractScope($payload);
        self::assertInstanceOf(Scope::class, $scope);
        self::assertTrue($scope->has('openid'));
    }

    /**
     * 自定义声明等值匹配
     */
    public function testAssertCustomEqualsMatch(): void
    {
        $payload = $this->makePayload();
        (new ClaimInspector())->assertCustomEquals($payload, 'tenant', 'acme');
        $this->expectNotToPerformAssertions();
    }

    /**
     * 自定义声明缺失
     */
    public function testAssertCustomEqualsMissing(): void
    {
        $payload = $this->makePayload();
        $this->expectException(TokenInvalidException::class);
        (new ClaimInspector())->assertCustomEquals($payload, 'missing_key', 'value');
    }

    /**
     * 自定义声明不匹配
     */
    public function testAssertCustomEqualsMismatch(): void
    {
        $payload = $this->makePayload();
        $this->expectException(TokenInvalidException::class);
        (new ClaimInspector())->assertCustomEquals($payload, 'tenant', 'other');
    }

    /**
     * platform 匹配
     */
    public function testAssertPlatformMatch(): void
    {
        $payload = $this->makePayload();
        (new ClaimInspector())->assertPlatform($payload, 'web');
        $this->expectNotToPerformAssertions();
    }

    /**
     * platform 不匹配
     */
    public function testAssertPlatformMismatch(): void
    {
        $payload = $this->makePayload();
        $this->expectException(TokenInvalidException::class);
        (new ClaimInspector())->assertPlatform($payload, 'app');
    }

    /**
     * platform 通配符 * 跳过校验
     */
    public function testAssertPlatformWildcardSkip(): void
    {
        $payload = $this->makePayload();
        (new ClaimInspector())->assertPlatform($payload, '*');
        $this->expectNotToPerformAssertions();
    }

    /**
     * 链式调用
     */
    public function testChainableAssertions(): void
    {
        $payload = $this->makePayload();
        $inspector = new ClaimInspector();
        $result = $inspector
            ->assertIssuer($payload, 'https://auth.example.com')
            ->assertAudience($payload, 'my-client-id')
            ->assertSubject($payload, 'user-123')
            ->assertPlatform($payload, 'web')
            ->assertScopesAll($payload, ['openid']);
        self::assertSame($inspector, $result);
    }
}
