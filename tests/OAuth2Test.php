<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\OAuth2\HybridProvider;
use Kode\Jwt\OAuth2\HybridTokenResponse;
use PHPUnit\Framework\TestCase;

final class OAuth2Test extends TestCase
{
    private HybridProvider $provider;

    protected function setUp(): void
    {
        $this->provider = new HybridProvider([
            'secret' => 'test_secret_key_for_oauth2',
            'access_token_ttl' => 3600,
            'refresh_token_ttl' => 86400,
            'issuer' => 'https://test.example.com',
        ]);
    }

    public function testGenerateAuthorizationCodeTokens(): void
    {
        $response = $this->provider->generateAuthorizationCodeTokens(
            clientId: 'test_client',
            userId: 123,
            scopes: ['openid', 'profile']
        );

        self::assertInstanceOf(HybridTokenResponse::class, $response);
        self::assertNotEmpty($response->accessToken);
        self::assertSame('Bearer', $response->tokenType);
        self::assertSame(3600, $response->expiresIn);
        self::assertNotNull($response->refreshToken);
        self::assertSame('openid profile', $response->scope);
    }

    public function testGenerateImplicitTokens(): void
    {
        $response = $this->provider->generateImplicitTokens(
            clientId: 'test_client',
            userId: 123,
            scopes: ['openid'],
            state: 'random_state'
        );

        self::assertInstanceOf(HybridTokenResponse::class, $response);
        self::assertNotEmpty($response->accessToken);
        self::assertSame('Bearer', $response->tokenType);
        self::assertSame('random_state', $response->state);
    }

    public function testGenerateClientCredentialsTokens(): void
    {
        $response = $this->provider->generateClientCredentialsTokens(
            clientId: 'test_client',
            scopes: ['api:read', 'api:write']
        );

        self::assertInstanceOf(HybridTokenResponse::class, $response);
        self::assertNotEmpty($response->accessToken);
        self::assertSame('Bearer', $response->tokenType);
        self::assertSame('api:read api:write', $response->scope);
        self::assertNull($response->refreshToken);
    }

    public function testHybridTokenResponseToArray(): void
    {
        $response = new HybridTokenResponse(
            accessToken: 'test_access_token',
            tokenType: 'Bearer',
            expiresIn: 3600,
            refreshToken: 'test_refresh_token',
            scope: 'openid profile'
        );

        $array = $response->toArray();

        self::assertSame('test_access_token', $array['access_token']);
        self::assertSame('Bearer', $array['token_type']);
        self::assertSame(3600, $array['expires_in']);
        self::assertSame('test_refresh_token', $array['refresh_token']);
        self::assertSame('openid profile', $array['scope']);
    }

    public function testHybridTokenResponseToJson(): void
    {
        $response = new HybridTokenResponse(
            accessToken: 'test_access_token',
            tokenType: 'Bearer',
            expiresIn: 3600
        );

        $json = $response->toJson();

        self::assertJson($json);
        self::assertStringContainsString('access_token', $json);
        self::assertStringContainsString('token_type', $json);
    }

    public function testFromAuthorizationCode(): void
    {
        $response = HybridTokenResponse::fromAuthorizationCode(
            accessToken: 'test_access_token',
            refreshToken: 'test_refresh_token',
            idToken: 'test_id_token',
            expiresIn: 3600,
            scope: 'openid'
        );

        self::assertSame('test_access_token', $response->accessToken);
        self::assertSame('test_refresh_token', $response->refreshToken);
        self::assertSame('test_id_token', $response->idToken);
    }

    public function testFromImplicit(): void
    {
        $response = HybridTokenResponse::fromImplicit(
            accessToken: 'test_access_token',
            idToken: 'test_id_token',
            expiresIn: 3600,
            state: 'test_state'
        );

        self::assertSame('test_access_token', $response->accessToken);
        self::assertSame('test_id_token', $response->idToken);
        self::assertSame('test_state', $response->state);
        self::assertNull($response->refreshToken);
    }

    public function testFromClientCredentials(): void
    {
        $response = HybridTokenResponse::fromClientCredentials(
            accessToken: 'test_access_token',
            expiresIn: 3600,
            scope: 'api:read'
        );

        self::assertSame('test_access_token', $response->accessToken);
        self::assertSame('api:read', $response->scope);
        self::assertNull($response->refreshToken);
        self::assertNull($response->idToken);
    }
}
