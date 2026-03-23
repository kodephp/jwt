<?php

declare(strict_types=1);

namespace Kode\Jwt\OAuth2;

use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Payload;
use Kode\Jwt\OpenId\IdTokenBuilder;

/**
 * OAuth2 混合模式提供者
 *
 * 支持 JWT 与 OAuth2 混合使用场景
 */
class HybridProvider
{
    protected Builder $accessTokenBuilder;
    protected Builder $refreshTokenBuilder;
    protected ?IdTokenBuilder $idTokenBuilder = null;

    public function __construct(
        protected array $config = []
    ) {
        $this->accessTokenBuilder = new Builder($config);
        $this->refreshTokenBuilder = new Builder($config);
    }

    /**
     * 设置 ID Token 构建器
     */
    public function setIdTokenBuilder(IdTokenBuilder $builder): self
    {
        $this->idTokenBuilder = $builder;
        return $this;
    }

    /**
     * 生成 Authorization Code 模式 Token
     */
    public function generateAuthorizationCodeTokens(
        string $clientId,
        string|int $userId,
        array $scopes = [],
        ?string $nonce = null
    ): HybridTokenResponse {
        $now = time();
        $accessTokenTtl = $this->config['access_token_ttl'] ?? 3600;
        $refreshTokenTtl = $this->config['refresh_token_ttl'] ?? 86400;

        // 生成 Access Token
        $this->accessTokenBuilder->setClaims([]);
        $this->accessTokenBuilder->setClaim('sub', (string) $userId);
        $this->accessTokenBuilder->setClaim('client_id', $clientId);
        $this->accessTokenBuilder->setClaim('type', 'access_token');
        $this->accessTokenBuilder->setIssuedAt($now);
        $this->accessTokenBuilder->setExpiration($now + $accessTokenTtl);

        if (!empty($scopes)) {
            $this->accessTokenBuilder->setClaim('scope', implode(' ', $scopes));
        }

        $accessToken = $this->accessTokenBuilder->build();

        // 生成 Refresh Token
        $this->refreshTokenBuilder->setClaims([]);
        $this->refreshTokenBuilder->setClaim('sub', (string) $userId);
        $this->refreshTokenBuilder->setClaim('client_id', $clientId);
        $this->refreshTokenBuilder->setClaim('type', 'refresh_token');
        $this->refreshTokenBuilder->setIssuedAt($now);
        $this->refreshTokenBuilder->setExpiration($now + $refreshTokenTtl);

        $refreshToken = $this->refreshTokenBuilder->build();

        // 生成 ID Token（如果配置了 OpenID）
        $idToken = null;
        if ($this->idTokenBuilder !== null && in_array('openid', $scopes, true)) {
            $this->idTokenBuilder->setSubject((string) $userId);
            $this->idTokenBuilder->setAudience($clientId);
            $this->idTokenBuilder->setIssuer($this->config['issuer'] ?? '');
            $this->idTokenBuilder->setIssuedAt($now);
            $this->idTokenBuilder->setExpiration($now + $accessTokenTtl);
            $this->idTokenBuilder->setAuthTime($now);

            if ($nonce !== null) {
                $this->idTokenBuilder->setNonce($nonce);
            }

            $idToken = $this->idTokenBuilder->build();
        }

        return HybridTokenResponse::fromAuthorizationCode(
            accessToken: $accessToken,
            refreshToken: $refreshToken,
            idToken: $idToken,
            expiresIn: $accessTokenTtl,
            scope: implode(' ', $scopes)
        );
    }

    /**
     * 生成 Implicit 模式 Token
     */
    public function generateImplicitTokens(
        string $clientId,
        string|int $userId,
        array $scopes = [],
        ?string $nonce = null,
        ?string $state = null
    ): HybridTokenResponse {
        $now = time();
        $accessTokenTtl = $this->config['access_token_ttl'] ?? 3600;

        // 生成 Access Token
        $this->accessTokenBuilder->setClaims([]);
        $this->accessTokenBuilder->setClaim('sub', (string) $userId);
        $this->accessTokenBuilder->setClaim('client_id', $clientId);
        $this->accessTokenBuilder->setClaim('type', 'access_token');
        $this->accessTokenBuilder->setIssuedAt($now);
        $this->accessTokenBuilder->setExpiration($now + $accessTokenTtl);

        if (!empty($scopes)) {
            $this->accessTokenBuilder->setClaim('scope', implode(' ', $scopes));
        }

        $accessToken = $this->accessTokenBuilder->build();

        // 生成 ID Token
        $idToken = null;
        if ($this->idTokenBuilder !== null && in_array('openid', $scopes, true)) {
            $this->idTokenBuilder->setSubject((string) $userId);
            $this->idTokenBuilder->setAudience($clientId);
            $this->idTokenBuilder->setIssuer($this->config['issuer'] ?? '');
            $this->idTokenBuilder->setIssuedAt($now);
            $this->idTokenBuilder->setExpiration($now + $accessTokenTtl);
            $this->idTokenBuilder->setAuthTime($now);

            if ($nonce !== null) {
                $this->idTokenBuilder->setNonce($nonce);
            }

            $idToken = $this->idTokenBuilder->build();
        }

        return HybridTokenResponse::fromImplicit(
            accessToken: $accessToken,
            idToken: $idToken,
            expiresIn: $accessTokenTtl,
            state: $state
        );
    }

    /**
     * 生成 Client Credentials 模式 Token
     */
    public function generateClientCredentialsTokens(
        string $clientId,
        array $scopes = []
    ): HybridTokenResponse {
        $now = time();
        $accessTokenTtl = $this->config['access_token_ttl'] ?? 3600;

        // 生成 Access Token
        $this->accessTokenBuilder->setClaims([]);
        $this->accessTokenBuilder->setClaim('sub', $clientId);
        $this->accessTokenBuilder->setClaim('client_id', $clientId);
        $this->accessTokenBuilder->setClaim('type', 'client_credentials');
        $this->accessTokenBuilder->setIssuedAt($now);
        $this->accessTokenBuilder->setExpiration($now + $accessTokenTtl);

        if (!empty($scopes)) {
            $this->accessTokenBuilder->setClaim('scope', implode(' ', $scopes));
        }

        $accessToken = $this->accessTokenBuilder->build();

        return HybridTokenResponse::fromClientCredentials(
            accessToken: $accessToken,
            expiresIn: $accessTokenTtl,
            scope: implode(' ', $scopes)
        );
    }

    /**
     * 使用 Refresh Token 刷新 Access Token
     */
    public function refreshAccessToken(
        string $refreshToken,
        string $clientId,
        callable $validateRefreshToken
    ): HybridTokenResponse {
        // 验证 Refresh Token
        $tokenData = $validateRefreshToken($refreshToken, $clientId);

        if ($tokenData === null) {
            throw new \InvalidArgumentException('Invalid refresh token');
        }

        return $this->generateAuthorizationCodeTokens(
            clientId: $clientId,
            userId: $tokenData['sub'] ?? $tokenData['uid'],
            scopes: $tokenData['scopes'] ?? []
        );
    }

    /**
     * 从 Payload 生成 Token
     */
    public function generateFromPayload(
        Payload $payload,
        string $clientId,
        array $scopes = []
    ): HybridTokenResponse {
        $now = time();
        $accessTokenTtl = $this->config['access_token_ttl'] ?? 3600;

        $this->accessTokenBuilder->fromPayload($payload);
        $this->accessTokenBuilder->setClaim('client_id', $clientId);
        $this->accessTokenBuilder->setClaim('type', 'access_token');

        if (!empty($scopes)) {
            $this->accessTokenBuilder->setClaim('scope', implode(' ', $scopes));
        }

        $accessToken = $this->accessTokenBuilder->build();

        return new HybridTokenResponse(
            accessToken: $accessToken,
            expiresIn: $accessTokenTtl,
            scope: implode(' ', $scopes)
        );
    }
}
