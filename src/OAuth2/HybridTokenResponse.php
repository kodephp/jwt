<?php

declare(strict_types=1);

namespace Kode\Jwt\OAuth2;

use Kode\Jwt\Token\Payload;

/**
 * OAuth2 混合模式 Token 响应
 */
final readonly class HybridTokenResponse
{
    public function __construct(
        public string $accessToken,
        public string $tokenType = 'Bearer',
        public int $expiresIn = 3600,
        public ?string $refreshToken = null,
        public ?string $idToken = null,
        public ?string $scope = null,
        public ?string $state = null,
        public array $additionalParams = []
    ) {
    }

    /**
     * 转换为数组
     */
    public function toArray(): array
    {
        $result = [
            'access_token' => $this->accessToken,
            'token_type' => $this->tokenType,
            'expires_in' => $this->expiresIn,
        ];

        if ($this->refreshToken !== null) {
            $result['refresh_token'] = $this->refreshToken;
        }

        if ($this->idToken !== null) {
            $result['id_token'] = $this->idToken;
        }

        if ($this->scope !== null) {
            $result['scope'] = $this->scope;
        }

        if ($this->state !== null) {
            $result['state'] = $this->state;
        }

        return array_merge($result, $this->additionalParams);
    }

    /**
     * 转换为 JSON
     */
    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_UNESCAPED_SLASHES);
    }

    /**
     * 创建 Authorization Code 模式响应
     */
    public static function fromAuthorizationCode(
        string $accessToken,
        ?string $refreshToken = null,
        ?string $idToken = null,
        int $expiresIn = 3600,
        ?string $scope = null
    ): self {
        return new self(
            accessToken: $accessToken,
            expiresIn: $expiresIn,
            refreshToken: $refreshToken,
            idToken: $idToken,
            scope: $scope
        );
    }

    /**
     * 创建 Implicit 模式响应
     */
    public static function fromImplicit(
        string $accessToken,
        ?string $idToken = null,
        int $expiresIn = 3600,
        ?string $state = null
    ): self {
        return new self(
            accessToken: $accessToken,
            expiresIn: $expiresIn,
            idToken: $idToken,
            state: $state
        );
    }

    /**
     * 创建 Client Credentials 模式响应
     */
    public static function fromClientCredentials(
        string $accessToken,
        int $expiresIn = 3600,
        ?string $scope = null
    ): self {
        return new self(
            accessToken: $accessToken,
            expiresIn: $expiresIn,
            scope: $scope
        );
    }
}
