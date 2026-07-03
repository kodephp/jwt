<?php

declare(strict_types=1);

namespace Kode\Jwt\Policy;

use Kode\Jwt\Claim\ClaimInspector;
use Kode\Jwt\Claim\Scope;
use Kode\Jwt\Exception\TokenInvalidException;
use Kode\Jwt\Token\Payload;

/**
 * Token 策略对象
 *
 * 以不可变值对象方式承载一套 Token 校验策略，配合 {@see ClaimInspector}
 * 完成对 Payload 的统一校验。避免散落在各 Guard / Controller 的零散判断。
 *
 * 策略字段：
 *  - expectedIssuer：iss 必须严格匹配
 *  - expectedAudience：aud 必须命中其一
 *  - expectedPlatform：platform 必须严格匹配
 *  - requiredScopes：scope 必须全部命中（hasAll）
 *  - anyScopes：scope 命中其一即可（hasAny）
 *  - requiredCustom：自定义声明等值匹配
 *  - clockSkew：时钟漂移容忍（秒）
 *  - ignoreExpiration：是否忽略过期（用于刷新流程）
 *
 * 用法：
 *   $policy = TokenPolicy::create()
 *       ->withIssuer('https://auth.example.com')
 *       ->withAudience('my-client-id')
 *       ->withRequiredScopes(['openid', 'profile'])
 *       ->withClockSkew(60);
 *   $policy->enforce($payload);
 *
 * 设计原则：
 *  - 不可变（readonly class）：每次 with* 返回新实例
 *  - 可组合：策略可继承、覆盖、合并
 *  - 失败抛出 TokenInvalidException，携带 jti 便于排查
 */
final readonly class TokenPolicy
{
    /**
     * 默认时钟漂移（秒）
     */
    public const int DEFAULT_CLOCK_SKEW = 30;

    /**
     * 构造函数
     *
     * @param string|null $expectedIssuer 期望的 issuer
     * @param string|array<string>|null $expectedAudience 期望的 audience
     * @param string|null $expectedPlatform 期望的 platform
     * @param array<string> $requiredScopes 必须全部命中的 scope
     * @param array<string> $anyScopes 命中其一即可的 scope
     * @param array<string, mixed> $requiredCustom 必须等值匹配的自定义声明
     * @param int $clockSkew 时钟漂移容忍（秒）
     * @param bool $ignoreExpiration 是否忽略过期校验
     */
    public function __construct(
        public ?string $expectedIssuer = null,
        public string|array|null $expectedAudience = null,
        public ?string $expectedPlatform = null,
        public array $requiredScopes = [],
        public array $anyScopes = [],
        public array $requiredCustom = [],
        public int $clockSkew = self::DEFAULT_CLOCK_SKEW,
        public bool $ignoreExpiration = false,
    ) {
    }

    /**
     * 创建空策略
     *
     * @return self
     */
    public static function create(): self
    {
        return new self();
    }

    /**
     * 从数组构造
     *
     * @param array<string, mixed> $data
     * @return self
     */
    public static function fromArray(array $data): self
    {
        return new self(
            expectedIssuer: isset($data['expected_issuer']) && is_string($data['expected_issuer'])
                ? $data['expected_issuer'] : null,
            expectedAudience: $data['expected_audience'] ?? null,
            expectedPlatform: isset($data['expected_platform']) && is_string($data['expected_platform'])
                ? $data['expected_platform'] : null,
            requiredScopes: isset($data['required_scopes']) && is_array($data['required_scopes'])
                ? array_map('strval', $data['required_scopes']) : [],
            anyScopes: isset($data['any_scopes']) && is_array($data['any_scopes'])
                ? array_map('strval', $data['any_scopes']) : [],
            requiredCustom: isset($data['required_custom']) && is_array($data['required_custom'])
                ? $data['required_custom'] : [],
            clockSkew: isset($data['clock_skew']) && is_int($data['clock_skew'])
                ? $data['clock_skew'] : self::DEFAULT_CLOCK_SKEW,
            ignoreExpiration: isset($data['ignore_expiration']) && is_bool($data['ignore_expiration'])
                ? $data['ignore_expiration'] : false,
        );
    }

    /**
     * 设置期望的 issuer
     */
    public function withIssuer(string $issuer): self
    {
        return new self(
            expectedIssuer: $issuer,
            expectedAudience: $this->expectedAudience,
            expectedPlatform: $this->expectedPlatform,
            requiredScopes: $this->requiredScopes,
            anyScopes: $this->anyScopes,
            requiredCustom: $this->requiredCustom,
            clockSkew: $this->clockSkew,
            ignoreExpiration: $this->ignoreExpiration,
        );
    }

    /**
     * 设置期望的 audience
     */
    public function withAudience(string|array $audience): self
    {
        return new self(
            expectedIssuer: $this->expectedIssuer,
            expectedAudience: $audience,
            expectedPlatform: $this->expectedPlatform,
            requiredScopes: $this->requiredScopes,
            anyScopes: $this->anyScopes,
            requiredCustom: $this->requiredCustom,
            clockSkew: $this->clockSkew,
            ignoreExpiration: $this->ignoreExpiration,
        );
    }

    /**
     * 设置期望的 platform
     */
    public function withPlatform(string $platform): self
    {
        return new self(
            expectedIssuer: $this->expectedIssuer,
            expectedAudience: $this->expectedAudience,
            expectedPlatform: $platform,
            requiredScopes: $this->requiredScopes,
            anyScopes: $this->anyScopes,
            requiredCustom: $this->requiredCustom,
            clockSkew: $this->clockSkew,
            ignoreExpiration: $this->ignoreExpiration,
        );
    }

    /**
     * 设置必须全部命中的 scope
     *
     * @param array<string> $scopes
     */
    public function withRequiredScopes(array $scopes): self
    {
        return new self(
            expectedIssuer: $this->expectedIssuer,
            expectedAudience: $this->expectedAudience,
            expectedPlatform: $this->expectedPlatform,
            requiredScopes: $scopes,
            anyScopes: $this->anyScopes,
            requiredCustom: $this->requiredCustom,
            clockSkew: $this->clockSkew,
            ignoreExpiration: $this->ignoreExpiration,
        );
    }

    /**
     * 设置命中其一即可的 scope
     *
     * @param array<string> $scopes
     */
    public function withAnyScopes(array $scopes): self
    {
        return new self(
            expectedIssuer: $this->expectedIssuer,
            expectedAudience: $this->expectedAudience,
            expectedPlatform: $this->expectedPlatform,
            requiredScopes: $this->requiredScopes,
            anyScopes: $scopes,
            requiredCustom: $this->requiredCustom,
            clockSkew: $this->clockSkew,
            ignoreExpiration: $this->ignoreExpiration,
        );
    }

    /**
     * 添加必须等值匹配的自定义声明
     */
    public function withRequiredCustom(string $key, mixed $value): self
    {
        $custom = $this->requiredCustom;
        $custom[$key] = $value;
        return new self(
            expectedIssuer: $this->expectedIssuer,
            expectedAudience: $this->expectedAudience,
            expectedPlatform: $this->expectedPlatform,
            requiredScopes: $this->requiredScopes,
            anyScopes: $this->anyScopes,
            requiredCustom: $custom,
            clockSkew: $this->clockSkew,
            ignoreExpiration: $this->ignoreExpiration,
        );
    }

    /**
     * 设置时钟漂移容忍（秒）
     */
    public function withClockSkew(int $seconds): self
    {
        return new self(
            expectedIssuer: $this->expectedIssuer,
            expectedAudience: $this->expectedAudience,
            expectedPlatform: $this->expectedPlatform,
            requiredScopes: $this->requiredScopes,
            anyScopes: $this->anyScopes,
            requiredCustom: $this->requiredCustom,
            clockSkew: $seconds,
            ignoreExpiration: $this->ignoreExpiration,
        );
    }

    /**
     * 设置是否忽略过期校验（用于刷新流程）
     */
    public function withIgnoreExpiration(bool $ignore = true): self
    {
        return new self(
            expectedIssuer: $this->expectedIssuer,
            expectedAudience: $this->expectedAudience,
            expectedPlatform: $this->expectedPlatform,
            requiredScopes: $this->requiredScopes,
            anyScopes: $this->anyScopes,
            requiredCustom: $this->requiredCustom,
            clockSkew: $this->clockSkew,
            ignoreExpiration: $ignore,
        );
    }

    /**
     * 对 Payload 执行策略校验
     *
     * @param Payload $payload 待校验的 Payload
     * @param ClaimInspector|null $inspector 注入自定义检查器（用于测试或扩展）
     * @return Payload 校验通过后原样返回，便于链式调用
     * @throws TokenInvalidException 当策略校验失败时
     */
    public function enforce(Payload $payload, ?ClaimInspector $inspector = null): Payload
    {
        $inspector = $inspector ?? new ClaimInspector();

        if ($this->expectedIssuer !== null) {
            $inspector->assertIssuer($payload, $this->expectedIssuer);
        }

        if ($this->expectedAudience !== null) {
            $inspector->assertAudience($payload, $this->expectedAudience);
        }

        if ($this->expectedPlatform !== null) {
            $inspector->assertPlatform($payload, $this->expectedPlatform);
        }

        // 时间窗口校验
        $inspector->assertTimeWindow($payload, $this->clockSkew, $this->ignoreExpiration);

        if ($this->requiredScopes !== []) {
            $inspector->assertScopesAll($payload, $this->requiredScopes);
        }

        if ($this->anyScopes !== []) {
            $inspector->assertScopesAny($payload, $this->anyScopes);
        }

        foreach ($this->requiredCustom as $key => $value) {
            $inspector->assertCustomEquals($payload, (string) $key, $value);
        }

        return $payload;
    }

    /**
     * 校验 Payload 是否满足策略（不抛异常）
     *
     * @param Payload $payload
     * @return bool
     */
    public function satisfies(Payload $payload): bool
    {
        try {
            $this->enforce($payload);
            return true;
        } catch (TokenInvalidException) {
            return false;
        }
    }

    /**
     * 提取策略所允许的 scope 集合
     *
     * @param Payload $payload
     * @return Scope 实际命中的 scope
     */
    public function extractAllowedScope(Payload $payload): Scope
    {
        $inspector = new ClaimInspector();
        $scope = $inspector->extractScope($payload);
        if ($this->requiredScopes !== []) {
            return $scope->intersect($this->requiredScopes);
        }
        return $scope;
    }

    /**
     * 序列化为数组（便于持久化或传输）
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'expected_issuer'    => $this->expectedIssuer,
            'expected_audience'  => $this->expectedAudience,
            'expected_platform'  => $this->expectedPlatform,
            'required_scopes'    => $this->requiredScopes,
            'any_scopes'         => $this->anyScopes,
            'required_custom'    => $this->requiredCustom,
            'clock_skew'         => $this->clockSkew,
            'ignore_expiration'  => $this->ignoreExpiration,
        ];
    }
}
