<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Key\Jwk;
use Kode\Jwt\Key\JwkSet;
use Kode\Jwt\OAuth2\JwksPublisher;
use Kode\Jwt\OAuth2\JwksResponse;
use PHPUnit\Framework\TestCase;

/**
 * JWKS 端点发布器单元测试
 *
 * 覆盖 RFC 7517 §5 / RFC 8414 jwks_uri 实现：
 *  - JSON 输出（剥离私钥参数）
 *  - ETag 计算
 *  - Cache-Control 头
 *  - If-None-Match 304 协商缓存
 */
class JwksEndpointTest extends TestCase
{
    /**
     * 构造测试用 JwkSet（含私钥参数）
     */
    private function makeJwkSet(): JwkSet
    {
        $jwk = Jwk::create('RSA', [
            'n' => 'public-modulus',
            'e' => 'AQAB',
            'd' => 'private-exponent',
            'p' => 'prime1',
            'q' => 'prime2',
        ], kid: 'kid-1', alg: 'RS256');

        return JwkSet::fromArray([$jwk]);
    }

    /**
     * 默认输出公钥集合，自动剥离私钥
     */
    public function testHandleReturnsPublicKeySet(): void
    {
        $publisher = new JwksPublisher($this->makeJwkSet());
        $response = $publisher->handle();

        self::assertTrue($response->isOk());
        self::assertSame(200, $response->status);
        self::assertSame('application/json; charset=UTF-8', $response->headers['Content-Type']);
        self::assertStringStartsWith('public, max-age=', $response->headers['Cache-Control']);
        self::assertNotEmpty($response->headers['ETag']);
        self::assertNotEmpty($response->body);

        // 响应体不应包含私钥参数
        self::assertStringNotContainsString('private-exponent', $response->body);
        self::assertStringNotContainsString('prime1', $response->body);
        self::assertStringNotContainsString('prime2', $response->body);

        // 应包含公钥参数
        self::assertStringContainsString('public-modulus', $response->body);
        self::assertStringContainsString('AQAB', $response->body);
        self::assertStringContainsString('kid-1', $response->body);
    }

    /**
     * JSON 输出格式符合 RFC 7517 §5
     */
    public function testToJsonContainsKeysArray(): void
    {
        $publisher = new JwksPublisher($this->makeJwkSet());
        $json = $publisher->toJson();

        self::assertTrue(json_validate($json));
        $data = json_decode($json, true);
        self::assertIsArray($data);
        self::assertArrayHasKey('keys', $data);
        self::assertCount(1, $data['keys']);
    }

    /**
     * ETag 稳定性：相同 JWK Set 应产生相同 ETag
     */
    public function testEtagIsStableForSameKeySet(): void
    {
        $publisher1 = new JwksPublisher($this->makeJwkSet());
        $publisher2 = new JwksPublisher($this->makeJwkSet());

        self::assertSame($publisher1->getEtag(), $publisher2->getEtag());
    }

    /**
     * ETag 格式：双引号包裹的 sha256
     */
    public function testEtagFormat(): void
    {
        $publisher = new JwksPublisher($this->makeJwkSet());
        $etag = $publisher->getEtag();

        self::assertStringStartsWith('"', $etag);
        self::assertStringEndsWith('"', $etag);
        // sha256 hex 长度为 64，加双引号共 66
        self::assertSame(66, strlen($etag));
    }

    /**
     * Cache-Control 默认 max-age=3600
     */
    public function testDefaultCacheControl(): void
    {
        $publisher = new JwksPublisher($this->makeJwkSet());
        self::assertSame('public, max-age=3600', $publisher->getCacheControl());
    }

    /**
     * 自定义 max-age
     */
    public function testCustomMaxAge(): void
    {
        $publisher = new JwksPublisher($this->makeJwkSet(), 600);
        self::assertSame('public, max-age=600', $publisher->getCacheControl());
    }

    /**
     * 负数 max-age 抛出异常
     */
    public function testNegativeMaxAgeThrows(): void
    {
        $this->expectException(JwtException::class);
        new JwksPublisher($this->makeJwkSet(), -1);
    }

    /**
     * If-None-Match 匹配 ETag 时返回 304
     */
    public function testIfNoneMatchReturns304(): void
    {
        $publisher = new JwksPublisher($this->makeJwkSet());
        $firstResponse = $publisher->handle();

        $etag = $firstResponse->headers['ETag'];
        $secondResponse = $publisher->handle(['if-none-match' => $etag]);

        self::assertTrue($secondResponse->isNotModified());
        self::assertSame(304, $secondResponse->status);
        self::assertSame('', $secondResponse->body);
    }

    /**
     * If-None-Match 不匹配时返回 200
     */
    public function testIfNoneMatchMismatchReturns200(): void
    {
        $publisher = new JwksPublisher($this->makeJwkSet());
        $response = $publisher->handle(['if-none-match' => '"different-etag"']);

        self::assertTrue($response->isOk());
        self::assertNotEmpty($response->body);
    }

    /**
     * If-None-Match 通配符 * 始终匹配
     */
    public function testIfNoneMatchWildcardAlwaysMatches(): void
    {
        $publisher = new JwksPublisher($this->makeJwkSet());
        $response = $publisher->handle(['if-none-match' => '*']);

        self::assertTrue($response->isNotModified());
    }

    /**
     * If-None-Match 多值逗号分隔，匹配其一即可
     */
    public function testIfNoneMatchMultipleValues(): void
    {
        $publisher = new JwksPublisher($this->makeJwkSet());
        $etag = $publisher->getEtag();

        $response = $publisher->handle(['if-none-match' => '"old-etag", ' . $etag]);
        self::assertTrue($response->isNotModified());
    }

    /**
     * 弱 ETag 比较：W/"abc" 与 "abc" 视为匹配
     */
    public function testWeakEtagComparison(): void
    {
        $publisher = new JwksPublisher($this->makeJwkSet());
        $etag = $publisher->getEtag();
        $weakEtag = 'W/' . $etag;

        $response = $publisher->handle(['if-none-match' => $weakEtag]);
        self::assertTrue($response->isNotModified());
    }

    /**
     * setJwkSet 后 ETag 变化
     */
    public function testSetJwkSetChangesEtag(): void
    {
        $publisher = new JwksPublisher($this->makeJwkSet());
        $originalEtag = $publisher->getEtag();

        $newJwk = Jwk::create('oct', ['k' => 'another-secret'], kid: 'kid-2', alg: 'HS256');
        $publisher->setJwkSet(new JwkSet([$newJwk]));

        self::assertNotSame($originalEtag, $publisher->getEtag());
    }

    /**
     * setMaxAge 后 Cache-Control 更新
     */
    public function testSetMaxAgeUpdatesCacheControl(): void
    {
        $publisher = new JwksPublisher($this->makeJwkSet(), 3600);
        $publisher->setMaxAge(120);

        self::assertSame('public, max-age=120', $publisher->getCacheControl());
    }

    /**
     * getJwks 始终返回公开 JWK Set
     */
    public function testGetJwksReturnsPublicSet(): void
    {
        $publisher = new JwksPublisher($this->makeJwkSet());
        $publicSet = $publisher->getJwks();

        self::assertInstanceOf(JwkSet::class, $publicSet);
        $jwk = $publicSet->get('kid-1');
        self::assertFalse($jwk->isPrivate());
    }
}
