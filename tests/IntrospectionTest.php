<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\OAuth2\IntrospectionResponse;
use Kode\Jwt\OAuth2\Introspector;
use Kode\Jwt\Storage\MemoryStorage;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Parser;
use Kode\Jwt\Token\Payload;
use PHPUnit\Framework\TestCase;

/**
 * Token Introspection 单元测试（RFC 7662）
 *
 * 覆盖 IntrospectionResponse 值对象与 Introspector 服务。
 */
class IntrospectionTest extends TestCase
{
    /**
     * 构造测试用 Builder/Parser
     */
    private function makeBuilderParser(): array
    {
        $config = [
            'algo' => 'HS256',
            'secret' => 'test_secret_for_introspection',
            'ttl' => 3600,
        ];
        return [new Builder($config), new Parser($config)];
    }

    /**
     * 构造测试用 Payload
     */
    private function makePayload(): Payload
    {
        return Payload::fromArray([
            'uid' => 123,
            'username' => 'alice',
            'platform' => 'web',
            'exp' => time() + 3600,
            'iat' => time(),
            'jti' => 'introspect_jti_001',
            'iss' => 'https://auth.example.com',
            'aud' => 'my-client-id',
            'sub' => 'user-123',
            'custom' => ['scope' => 'openid profile', 'tenant' => 'acme'],
        ]);
    }

    /**
     * active=true 响应 toArray 包含完整字段
     */
    public function testActiveResponseToArray(): void
    {
        $payload = $this->makePayload();
        $response = IntrospectionResponse::fromPayload($payload, 'my-client-id');

        $array = $response->toArray();

        self::assertTrue($response->isActive());
        self::assertTrue($array['active']);
        self::assertSame('my-client-id', $array['client_id']);
        self::assertSame('alice', $array['username']);
        self::assertSame('Bearer', $array['token_type']);
        self::assertSame($payload->exp, $array['exp']);
        self::assertSame($payload->iat, $array['iat']);
        self::assertSame('user-123', $array['sub']);
        self::assertSame('my-client-id', $array['aud']);
        self::assertSame('https://auth.example.com', $array['iss']);
        self::assertSame('introspect_jti_001', $array['jti']);
        self::assertSame('openid profile', $array['scope']);
        self::assertSame('web', $array['platform']);
    }

    /**
     * active=false 响应仅包含 active 字段
     */
    public function testInactiveResponseOnlyContainsActive(): void
    {
        $response = IntrospectionResponse::inactive();

        self::assertFalse($response->isActive());
        self::assertSame(['active' => false], $response->toArray());
    }

    /**
     * inactive 响应的 JSON 仅含 {"active":false}
     */
    public function testInactiveResponseJson(): void
    {
        $response = IntrospectionResponse::inactive();
        self::assertSame('{"active":false}', $response->toJson());
    }

    /**
     * active 响应的 JSON 是合法 JSON
     */
    public function testActiveResponseJsonIsValid(): void
    {
        $payload = $this->makePayload();
        $response = IntrospectionResponse::fromPayload($payload, 'client-x');

        $json = $response->toJson();
        self::assertTrue(json_validate($json));
        $data = json_decode($json, true);
        self::assertTrue($data['active']);
    }

    /**
     * fromPayload 未提供 clientId 时为 null
     */
    public function testFromPayloadWithoutClientId(): void
    {
        $payload = $this->makePayload();
        $response = IntrospectionResponse::fromPayload($payload);

        $array = $response->toArray();
        self::assertArrayNotHasKey('client_id', $array);
    }

    /**
     * Introspector 对有效 Token 返回 active=true
     */
    public function testIntrospectorReturnsActiveForValidToken(): void
    {
        [$builder, $parser] = $this->makeBuilderParser();
        $token = $builder->fromPayload($this->makePayload())->build();

        $storage = new MemoryStorage();
        $introspector = new Introspector($parser, $storage);

        $response = $introspector->introspect($token, 'web', 'client-id');

        self::assertTrue($response->isActive());
        self::assertSame('alice', $response->username);
        self::assertSame('client-id', $response->clientId);
    }

    /**
     * Introspector 对无效 Token 返回 active=false
     */
    public function testIntrospectorReturnsInactiveForInvalidToken(): void
    {
        [$builder, $parser] = $this->makeBuilderParser();
        $storage = new MemoryStorage();
        $introspector = new Introspector($parser, $storage);

        $response = $introspector->introspect('invalid.token.format');

        self::assertFalse($response->isActive());
    }

    /**
     * Introspector 对已过期 Token 返回 active=false
     */
    public function testIntrospectorReturnsInactiveForExpiredToken(): void
    {
        $config = [
            'algo' => 'HS256',
            'secret' => 'test_secret_for_introspection',
            'ttl' => 3600,
        ];
        $builder = new Builder($config);
        $parser = new Parser($config);

        $payload = Payload::fromArray([
            'uid' => 123,
            'username' => 'alice',
            'platform' => 'web',
            'exp' => time() - 100,
            'iat' => time() - 3600,
            'jti' => 'expired_jti_001',
            'iss' => 'https://auth.example.com',
            'aud' => 'my-client-id',
            'sub' => 'user-123',
        ]);
        $token = $builder->fromPayload($payload)->build();

        $storage = new MemoryStorage();
        $introspector = new Introspector($parser, $storage);

        $response = $introspector->introspect($token);
        self::assertFalse($response->isActive());
    }

    /**
     * Introspector 对黑名单 JTI 返回 active=false
     */
    public function testIntrospectorReturnsInactiveForBlacklistedToken(): void
    {
        [$builder, $parser] = $this->makeBuilderParser();
        $payload = $this->makePayload();
        $token = $builder->fromPayload($payload)->build();

        $storage = new MemoryStorage();
        $storage->blacklist($payload->jti, 3600);

        $introspector = new Introspector($parser, $storage);
        $response = $introspector->introspect($token);

        self::assertFalse($response->isActive());
    }

    /**
     * Introspector 平台不匹配返回 active=false
     */
    public function testIntrospectorReturnsInactiveForPlatformMismatch(): void
    {
        [$builder, $parser] = $this->makeBuilderParser();
        $token = $builder->fromPayload($this->makePayload())->build();

        $storage = new MemoryStorage();
        $introspector = new Introspector($parser, $storage);

        $response = $introspector->introspect($token, 'app');
        self::assertFalse($response->isActive());
    }

    /**
     * fromPayload 方法（基于已校验 Payload）
     */
    public function testIntrospectorFromPayload(): void
    {
        $payload = $this->makePayload();
        $storage = new MemoryStorage();
        $parser = new Parser(['secret' => 'x', 'algo' => 'HS256']);

        $introspector = new Introspector($parser, $storage);
        $response = $introspector->fromPayload($payload, 'client-id');

        self::assertTrue($response->isActive());
        self::assertSame('alice', $response->username);
    }

    /**
     * fromPayload 方法（Payload 在黑名单中）
     */
    public function testIntrospectorFromPayloadBlacklisted(): void
    {
        $payload = $this->makePayload();
        $storage = new MemoryStorage();
        $storage->blacklist($payload->jti, 3600);

        $parser = new Parser(['secret' => 'x', 'algo' => 'HS256']);
        $introspector = new Introspector($parser, $storage);

        $response = $introspector->fromPayload($payload);
        self::assertFalse($response->isActive());
    }

    /**
     * setParser / setStorage / setLogger 链式
     */
    public function testSettersAreChainable(): void
    {
        [$builder, $parser] = $this->makeBuilderParser();
        $storage = new MemoryStorage();

        $introspector = new Introspector($parser, $storage);
        $newParser = new Parser(['secret' => 'new', 'algo' => 'HS256']);
        $newStorage = new MemoryStorage();

        $result = $introspector->setParser($newParser)->setStorage($newStorage);
        self::assertSame($introspector, $result);
    }

    /**
     * 签名错误返回 active=false（不抛出异常）
     */
    public function testIntrospectorReturnsInactiveForSignatureFailure(): void
    {
        $config = [
            'algo' => 'HS256',
            'secret' => 'different_secret',
            'ttl' => 3600,
        ];
        $builder = new Builder($config);
        $payload = $this->makePayload();
        $token = $builder->fromPayload($payload)->build();

        // 使用不同密钥的 parser
        $parser = new Parser([
            'algo' => 'HS256',
            'secret' => 'wrong_secret',
            'ttl' => 3600,
        ]);
        $storage = new MemoryStorage();
        $introspector = new Introspector($parser, $storage);

        $response = $introspector->introspect($token);
        self::assertFalse($response->isActive());
    }
}
