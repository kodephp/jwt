<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\OAuth2\JwksResponse;
use Kode\Jwt\OpenId\DiscoveryConfiguration;
use Kode\Jwt\OpenId\DiscoveryPublisher;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery 单元测试（RFC 8414）
 *
 * 覆盖 DiscoveryConfiguration 值对象与 DiscoveryPublisher 端点发布器。
 */
class DiscoveryTest extends TestCase
{
    /**
     * 构造测试用 DiscoveryConfiguration
     */
    private function makeConfiguration(): DiscoveryConfiguration
    {
        return new DiscoveryConfiguration(
            issuer: 'https://auth.example.com',
            authorizationEndpoint: 'https://auth.example.com/authorize',
            tokenEndpoint: 'https://auth.example.com/token',
            jwksUri: 'https://auth.example.com/jwks',
            userinfoEndpoint: 'https://auth.example.com/userinfo',
            introspectionEndpoint: 'https://auth.example.com/introspect',
            revocationEndpoint: 'https://auth.example.com/revoke',
            endSessionEndpoint: 'https://auth.example.com/logout',
        );
    }

    /**
     * 必填字段缺失抛出异常
     */
    public function testConstructorRequiresEssentialEndpoints(): void
    {
        $this->expectException(JwtException::class);
        new DiscoveryConfiguration(
            issuer: '',
            authorizationEndpoint: 'https://auth.example.com/authorize',
            tokenEndpoint: 'https://auth.example.com/token',
            jwksUri: 'https://auth.example.com/jwks',
        );
    }

    /**
     * issuer 为空抛出异常
     */
    public function testEmptyIssuerThrows(): void
    {
        $this->expectException(JwtException::class);
        new DiscoveryConfiguration(
            issuer: '',
            authorizationEndpoint: 'a',
            tokenEndpoint: 'b',
            jwksUri: 'c',
        );
    }

    /**
     * toArray 包含必填字段
     */
    public function testToArrayContainsRequiredFields(): void
    {
        $config = $this->makeConfiguration();
        $data = $config->toArray();

        self::assertSame('https://auth.example.com', $data['issuer']);
        self::assertSame('https://auth.example.com/authorize', $data['authorization_endpoint']);
        self::assertSame('https://auth.example.com/token', $data['token_endpoint']);
        self::assertSame('https://auth.example.com/jwks', $data['jwks_uri']);
        self::assertSame('https://auth.example.com/userinfo', $data['userinfo_endpoint']);
        self::assertSame('https://auth.example.com/introspect', $data['introspection_endpoint']);
        self::assertSame('https://auth.example.com/revoke', $data['revocation_endpoint']);
        self::assertSame('https://auth.example.com/logout', $data['end_session_endpoint']);
        self::assertContains('openid', $data['scopes_supported']);
        self::assertContains('code', $data['response_types_supported']);
        self::assertContains('authorization_code', $data['grant_types_supported']);
        self::assertContains('RS256', $data['id_token_signing_alg_values_supported']);
        self::assertContains('sub', $data['claims_supported']);
    }

    /**
     * 可选端点为 null 时不出现在数组中
     */
    public function testOptionalEndpointsAreOmittedWhenNull(): void
    {
        $config = new DiscoveryConfiguration(
            issuer: 'https://auth.example.com',
            authorizationEndpoint: 'https://auth.example.com/authorize',
            tokenEndpoint: 'https://auth.example.com/token',
            jwksUri: 'https://auth.example.com/jwks',
        );

        $data = $config->toArray();
        self::assertArrayNotHasKey('userinfo_endpoint', $data);
        self::assertArrayNotHasKey('introspection_endpoint', $data);
        self::assertArrayNotHasKey('revocation_endpoint', $data);
        self::assertArrayNotHasKey('end_session_endpoint', $data);
    }

    /**
     * extra 字段被合并到 toArray
     */
    public function testExtraFieldsAreMerged(): void
    {
        $config = new DiscoveryConfiguration(
            issuer: 'https://auth.example.com',
            authorizationEndpoint: 'https://auth.example.com/authorize',
            tokenEndpoint: 'https://auth.example.com/token',
            jwksUri: 'https://auth.example.com/jwks',
            extra: ['require_auth_time' => true, 'code_challenge_methods_supported' => ['S256']],
        );

        $data = $config->toArray();
        self::assertTrue($data['require_auth_time']);
        self::assertSame(['S256'], $data['code_challenge_methods_supported']);
    }

    /**
     * fromArray 解析
     */
    public function testFromArrayParsesStandardFields(): void
    {
        $data = [
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/authorize',
            'token_endpoint' => 'https://auth.example.com/token',
            'jwks_uri' => 'https://auth.example.com/jwks',
            'userinfo_endpoint' => 'https://auth.example.com/userinfo',
            'require_auth_time' => true,
        ];

        $config = DiscoveryConfiguration::fromArray($data);

        self::assertSame('https://auth.example.com', $config->issuer);
        self::assertSame('https://auth.example.com/userinfo', $config->userinfoEndpoint);
        self::assertArrayHasKey('require_auth_time', $config->extra);
        self::assertTrue($config->extra['require_auth_time']);
    }

    /**
     * fromArray 缺失必填字段抛出异常
     */
    public function testFromArrayMissingRequiredThrows(): void
    {
        $this->expectException(JwtException::class);
        DiscoveryConfiguration::fromArray([
            'issuer' => 'https://auth.example.com',
            'authorization_endpoint' => 'https://auth.example.com/authorize',
        ]);
    }

    /**
     * fromJson / toJson 双向
     */
    public function testFromJsonAndToJsonRoundtrip(): void
    {
        $config = $this->makeConfiguration();
        $json = $config->toJson();

        self::assertTrue(json_validate($json));

        $restored = DiscoveryConfiguration::fromJson($json);
        self::assertSame($config->issuer, $restored->issuer);
        self::assertSame($config->authorizationEndpoint, $restored->authorizationEndpoint);
        self::assertSame($config->tokenEndpoint, $restored->tokenEndpoint);
        self::assertSame($config->jwksUri, $restored->jwksUri);
        self::assertSame($config->userinfoEndpoint, $restored->userinfoEndpoint);
    }

    /**
     * fromJson 非法 JSON 抛出异常
     */
    public function testFromJsonInvalidThrows(): void
    {
        $this->expectException(JwtException::class);
        DiscoveryConfiguration::fromJson('not json');
    }

    /**
     * DiscoveryPublisher 默认 200 响应
     */
    public function testPublisherHandleReturns200(): void
    {
        $publisher = new DiscoveryPublisher($this->makeConfiguration());
        $response = $publisher->handle();

        self::assertInstanceOf(JwksResponse::class, $response);
        self::assertTrue($response->isOk());
        self::assertSame(200, $response->status);
        self::assertSame('application/json; charset=UTF-8', $response->headers['Content-Type']);
        self::assertStringStartsWith('public, max-age=', $response->headers['Cache-Control']);
        self::assertNotEmpty($response->headers['ETag']);
        self::assertNotEmpty($response->body);
        self::assertTrue(json_validate($response->body));
    }

    /**
     * ETag 稳定性
     */
    public function testPublisherEtagIsStable(): void
    {
        $publisher1 = new DiscoveryPublisher($this->makeConfiguration());
        $publisher2 = new DiscoveryPublisher($this->makeConfiguration());

        self::assertSame($publisher1->getEtag(), $publisher2->getEtag());
    }

    /**
     * If-None-Match 匹配返回 304
     */
    public function testPublisherIfNoneMatchReturns304(): void
    {
        $publisher = new DiscoveryPublisher($this->makeConfiguration());
        $first = $publisher->handle();
        $etag = $first->headers['ETag'];

        $second = $publisher->handle(['if-none-match' => $etag]);
        self::assertTrue($second->isNotModified());
        self::assertSame('', $second->body);
    }

    /**
     * If-None-Match 通配符始终匹配
     */
    public function testPublisherWildcardEtagMatches(): void
    {
        $publisher = new DiscoveryPublisher($this->makeConfiguration());
        $response = $publisher->handle(['if-none-match' => '*']);
        self::assertTrue($response->isNotModified());
    }

    /**
     * 默认 max-age=3600
     */
    public function testPublisherDefaultMaxAge(): void
    {
        $publisher = new DiscoveryPublisher($this->makeConfiguration());
        self::assertSame('public, max-age=3600', $publisher->getCacheControl());
    }

    /**
     * 自定义 max-age
     */
    public function testPublisherCustomMaxAge(): void
    {
        $publisher = new DiscoveryPublisher($this->makeConfiguration(), 600);
        self::assertSame('public, max-age=600', $publisher->getCacheControl());
    }

    /**
     * 负数 max-age 抛出异常
     */
    public function testPublisherNegativeMaxAgeThrows(): void
    {
        $this->expectException(JwtException::class);
        new DiscoveryPublisher($this->makeConfiguration(), -1);
    }

    /**
     * setConfiguration / setMaxAge 链式
     */
    public function testPublisherSettersAreChainable(): void
    {
        $publisher = new DiscoveryPublisher($this->makeConfiguration());
        $newConfig = new DiscoveryConfiguration(
            issuer: 'https://auth2.example.com',
            authorizationEndpoint: 'https://auth2.example.com/authorize',
            tokenEndpoint: 'https://auth2.example.com/token',
            jwksUri: 'https://auth2.example.com/jwks',
        );

        $result = $publisher->setConfiguration($newConfig)->setMaxAge(120);
        self::assertSame($publisher, $result);
        self::assertSame('https://auth2.example.com', $publisher->getConfiguration()->issuer);
        self::assertSame('public, max-age=120', $publisher->getCacheControl());
    }

    /**
     * OIDC / OAuth2 标准端点路径常量
     */
    public function testWellKnownPathConstants(): void
    {
        self::assertSame('/.well-known/openid-configuration', DiscoveryPublisher::OIDC_PATH);
        self::assertSame('/.well-known/oauth-authorization-server', DiscoveryPublisher::OAUTH_PATH);
    }
}
