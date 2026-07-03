<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Claim\Scope;
use Kode\Jwt\Exception\JwtException;
use PHPUnit\Framework\TestCase;

/**
 * Scope 值对象单元测试
 *
 * 覆盖 fromString / fromArray / has / hasAny / hasAll / intersect / diff / merge / 校验。
 */
class ScopeTest extends TestCase
{
    /**
     * 从空格分隔字符串构造并去重
     */
    public function testFromStringParsesAndDeduplicates(): void
    {
        $scope = Scope::fromString('openid profile  profile email');

        self::assertSame(['openid', 'profile', 'email'], $scope->scopes);
        self::assertSame('openid profile email', $scope->toString());
        self::assertSame(3, count($scope));
    }

    /**
     * 空字符串返回空 Scope
     */
    public function testEmptyStringReturnsEmptyScope(): void
    {
        $scope = Scope::fromString('');

        self::assertTrue($scope->isEmpty());
        self::assertSame('', $scope->toString());
        self::assertSame([], $scope->toArray());
    }

    /**
     * 非法字符抛出异常
     */
    public function testInvalidCharacterThrows(): void
    {
        $this->expectException(JwtException::class);
        Scope::fromString('openid;injection');
    }

    /**
     * has / hasAny / hasAll
     */
    public function testHasOperations(): void
    {
        $scope = Scope::fromString('openid profile email');

        self::assertTrue($scope->has('openid'));
        self::assertFalse($scope->has('admin'));

        self::assertTrue($scope->hasAny(['admin', 'openid']));
        self::assertFalse($scope->hasAny(['admin', 'write']));

        self::assertTrue($scope->hasAll(['openid', 'profile']));
        self::assertFalse($scope->hasAll(['openid', 'admin']));
    }

    /**
     * 交集 / 差集 / 合并
     */
    public function testSetOperations(): void
    {
        $scope = Scope::fromString('openid profile email');

        $inter = $scope->intersect(['openid', 'admin']);
        self::assertSame(['openid'], $inter->scopes);

        $diff = $scope->diff(['openid']);
        self::assertSame(['profile', 'email'], $diff->scopes);

        $merged = $scope->merge(['admin', 'openid']);
        self::assertSame(['openid', 'profile', 'email', 'admin'], $merged->scopes);
    }

    /**
     * allAllowed 白名单校验
     */
    public function testAllAllowed(): void
    {
        $scope = Scope::fromString('openid profile');

        self::assertTrue($scope->allAllowed(['openid', 'profile', 'email', 'offline_access']));
        self::assertFalse($scope->allAllowed(['openid', 'admin']));
        self::assertTrue($scope->allStandard());
    }

    /**
     * 非 OIDC 标准 scope 时 allStandard 返回 false
     */
    public function testAllStandardReturnsFalseForCustomScope(): void
    {
        $scope = Scope::fromString('openid custom_scope');
        self::assertFalse($scope->allStandard());
    }

    /**
     * JSON 反序列化
     */
    public function testFromJsonArray(): void
    {
        $scope = Scope::fromJson('["openid","profile"]');
        self::assertSame(['openid', 'profile'], $scope->scopes);
    }

    /**
     * JSON 字符串形式
     */
    public function testFromJsonString(): void
    {
        $scope = Scope::fromJson('"openid profile"');
        self::assertSame(['openid', 'profile'], $scope->scopes);
    }

    /**
     * toArray / toJson 输出
     */
    public function testToArrayAndToJson(): void
    {
        $scope = Scope::fromString('openid profile');

        self::assertSame(['openid', 'profile'], $scope->toArray());
        self::assertSame('["openid","profile"]', $scope->toJson());
    }

    /**
     * __toString 魔法方法
     */
    public function testToStringMagicMethod(): void
    {
        $scope = Scope::fromString('openid profile');
        self::assertSame('openid profile', (string) $scope);
    }
}
