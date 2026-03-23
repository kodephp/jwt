<?php

declare(strict_types=1);

namespace Kode\Jwt\OpenId;

use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Payload;

/**
 * OpenID Connect ID Token 构建器
 */
class IdTokenBuilder
{
    protected Builder $builder;

    /**
     * @var array<string> 已授权的 scope 列表
     */
    protected array $scopes = ['openid'];

    /**
     * @var array<string, mixed> 认证上下文引用
     */
    protected array $acrValues = [];

    public function __construct(array $config = [])
    {
        $this->builder = new Builder($config);
        $this->builder->setHeader('typ', 'JWT');
    }

    /**
     * 设置主体标识（用户唯一标识）
     */
    public function setSubject(string $sub): self
    {
        $this->builder->setClaim('sub', $sub);
        return $this;
    }

    /**
     * 设置受众（客户端 ID）
     */
    public function setAudience(string|array $aud): self
    {
        $this->builder->setAudience($aud);
        return $this;
    }

    /**
     * 设置签发者
     */
    public function setIssuer(string $iss): self
    {
        $this->builder->setIssuer($iss);
        return $this;
    }

    /**
     * 设置过期时间
     */
    public function setExpiration(int $exp): self
    {
        $this->builder->setExpiration($exp);
        return $this;
    }

    /**
     * 设置签发时间
     */
    public function setIssuedAt(int $iat): self
    {
        $this->builder->setIssuedAt($iat);
        return $this;
    }

    /**
     * 设置认证时间
     */
    public function setAuthTime(int $authTime): self
    {
        $this->builder->setClaim('auth_time', $authTime);
        return $this;
    }

    /**
     * 设置 nonce 值
     */
    public function setNonce(string $nonce): self
    {
        $this->builder->setClaim('nonce', $nonce);
        return $this;
    }

    /**
     * 设置授权范围
     *
     * @param array<string> $scopes
     */
    public function setScopes(array $scopes): self
    {
        $this->scopes = array_unique(array_merge(['openid'], $scopes));
        return $this;
    }

    /**
     * 添加单个 scope
     */
    public function addScope(string $scope): self
    {
        if (!in_array($scope, $this->scopes, true)) {
            $this->scopes[] = $scope;
        }
        return $this;
    }

    /**
     * 设置 ACR 值
     */
    public function setAcr(string $acr): self
    {
        $this->builder->setClaim('acr', $acr);
        return $this;
    }

    /**
     * 设置 AMR 值（认证方法引用）
     *
     * @param array<string> $amr
     */
    public function setAmr(array $amr): self
    {
        $this->builder->setClaim('amr', $amr);
        return $this;
    }

    /**
     * 设置授权方（代理授权场景）
     */
    public function setAuthorizedParty(string $azp): self
    {
        $this->builder->setClaim('azp', $azp);
        return $this;
    }

    /**
     * 设置访问令牌哈希
     */
    public function setAccessTokenHash(string $atHash): self
    {
        $this->builder->setClaim('at_hash', $atHash);
        return $this;
    }

    /**
     * 设置授权码哈希
     */
    public function setCodeHash(string $cHash): self
    {
        $this->builder->setClaim('c_hash', $cHash);
        return $this;
    }

    /**
     * 设置用户信息
     */
    public function setUserInfo(UserInfo $userInfo): self
    {
        $data = $userInfo->toArray();
        foreach ($data as $key => $value) {
            if ($key !== 'sub') {
                $this->builder->setClaim($key, $value);
            }
        }
        return $this;
    }

    /**
     * 从 Payload 设置声明
     */
    public function fromPayload(Payload $payload): self
    {
        $this->builder->fromPayload($payload);
        return $this;
    }

    /**
     * 设置自定义声明
     */
    public function setClaim(string $key, mixed $value): self
    {
        $this->builder->setClaim($key, $value);
        return $this;
    }

    /**
     * 构建 ID Token
     */
    public function build(): string
    {
        if (!in_array('openid', $this->scopes, true)) {
            $this->scopes[] = 'openid';
        }

        $this->builder->setClaim('scope', implode(' ', $this->scopes));

        return $this->builder->build();
    }

    /**
     * 获取底层 Builder 实例
     */
    public function getBuilder(): Builder
    {
        return $this->builder;
    }
}
