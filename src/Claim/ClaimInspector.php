<?php

declare(strict_types=1);

namespace Kode\Jwt\Claim;

use Kode\Jwt\Exception\TokenInvalidException;
use Kode\Jwt\Token\Payload;

/**
 * Claim 声明检查器
 *
 * 统一处理 Token 声明（claim）的业务校验逻辑，避免在 Guard / Introspector /
 * 业务层重复实现。覆盖以下检查：
 *
 *  1. iss（issuer）严格匹配
 *  2. aud（audience）包含期望的受众
 *  3. sub（subject）非空
 *  4. exp / nbf / iat 时间窗口（含时钟漂移容忍）
 *  5. scope 是否满足期望集合（hasAll / hasAny）
 *  6. 自定义声明等值匹配
 *
 * 设计原则：
 *  - 纯无状态：所有期望值通过方法参数传入，不持有运行时上下文
 *  - 校验失败抛出 TokenInvalidException，与 Parser 一致
 *  - 支持链式校验：assertIssuer()->assertAudience()->assertScopes()
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7519#section-4 RFC 7519 §4 - JWT Claims
 */
final class ClaimInspector
{
    /**
     * 默认时钟漂移容忍（秒）
     */
    public const int DEFAULT_CLOCK_SKEW = 30;

    /**
     * 校验 issuer（签发者）严格匹配
     *
     * @param Payload $payload
     * @param string $expectedIssuer 期望的 issuer
     * @return self
     * @throws TokenInvalidException 当 issuer 不匹配时
     */
    public function assertIssuer(Payload $payload, string $expectedIssuer): self
    {
        if ($expectedIssuer === '') {
            return $this;
        }
        if ($payload->issuer === null || !hash_equals($expectedIssuer, $payload->issuer)) {
            throw new TokenInvalidException(
                'Token issuer 不匹配',
                reason: sprintf('expected=%s actual=%s', $expectedIssuer, $payload->issuer ?? '(null)'),
                jti: $payload->jti
            );
        }
        return $this;
    }

    /**
     * 校验 audience（受众）包含期望值
     *
     * @param Payload $payload
     * @param string|array<string> $expectedAudience 期望的受众（单个或多个，命中其一即可）
     * @return self
     * @throws TokenInvalidException 当 audience 不匹配时
     */
    public function assertAudience(Payload $payload, string|array $expectedAudience): self
    {
        if ($expectedAudience === '' || $expectedAudience === []) {
            return $this;
        }

        $actualAud = $payload->audience;
        if ($actualAud === null) {
            throw new TokenInvalidException(
                'Token 缺失 audience 声明',
                reason: 'audience is null',
                jti: $payload->jti
            );
        }

        $expectedList = is_array($expectedAudience) ? $expectedAudience : [$expectedAudience];
        $actualList = is_array($actualAud) ? $actualAud : [$actualAud];

        foreach ($expectedList as $expected) {
            if (in_array($expected, $actualList, true)) {
                return $this;
            }
        }

        throw new TokenInvalidException(
            'Token audience 不匹配',
            reason: sprintf('expected=%s actual=%s', implode(',', $expectedList), implode(',', $actualList)),
            jti: $payload->jti
        );
    }

    /**
     * 校验 subject（主体）非空且严格匹配
     *
     * @param Payload $payload
     * @param string|null $expectedSubject 期望的 subject，传 null 则仅校验非空
     * @return self
     * @throws TokenInvalidException
     */
    public function assertSubject(Payload $payload, ?string $expectedSubject = null): self
    {
        if ($payload->subject === null || $payload->subject === '') {
            throw new TokenInvalidException(
                'Token 缺失 subject 声明',
                reason: 'subject is null or empty',
                jti: $payload->jti
            );
        }
        if ($expectedSubject !== null && !hash_equals($expectedSubject, $payload->subject)) {
            throw new TokenInvalidException(
                'Token subject 不匹配',
                reason: sprintf('expected=%s actual=%s', $expectedSubject, $payload->subject),
                jti: $payload->jti
            );
        }
        return $this;
    }

    /**
     * 校验时间窗口：exp / nbf / iat
     *
     * @param Payload $payload
     * @param int $clockSkew 时钟漂移容忍（秒），默认 30
     * @param bool $ignoreExpiration 是否忽略过期校验（用于刷新流程）
     * @return self
     * @throws TokenInvalidException 当过期 / 尚未生效 / iat 在未来时
     */
    public function assertTimeWindow(
        Payload $payload,
        int $clockSkew = self::DEFAULT_CLOCK_SKEW,
        bool $ignoreExpiration = false
    ): self {
        $now = time();

        // 过期校验
        if (!$ignoreExpiration && $payload->exp > 0 && $now > ($payload->exp + $clockSkew)) {
            throw new TokenInvalidException(
                'Token 已过期',
                reason: sprintf('exp=%d now=%d skew=%d', $payload->exp, $now, $clockSkew),
                jti: $payload->jti
            );
        }

        // nbf 校验（在 custom 中）
        $nbf = $payload->custom['nbf'] ?? null;
        if (is_int($nbf) && $now < ($nbf - $clockSkew)) {
            throw new TokenInvalidException(
                'Token 尚未生效',
                reason: sprintf('nbf=%d now=%d skew=%d', $nbf, $now, $clockSkew),
                jti: $payload->jti
            );
        }

        // iat 校验：iat 不应在未来（容忍时钟漂移）
        if ($payload->iat > 0 && $now < ($payload->iat - $clockSkew)) {
            throw new TokenInvalidException(
                'Token iat 异常：签发时间在未来',
                reason: sprintf('iat=%d now=%d skew=%d', $payload->iat, $now, $clockSkew),
                jti: $payload->jti
            );
        }

        return $this;
    }

    /**
     * 校验 scope 是否包含全部期望 scope
     *
     * @param Payload $payload
     * @param array<string> $requiredScopes 必须全部命中的 scope 列表
     * @return self
     * @throws TokenInvalidException
     */
    public function assertScopesAll(Payload $payload, array $requiredScopes): self
    {
        if ($requiredScopes === []) {
            return $this;
        }
        $scope = $this->extractScope($payload);
        foreach ($requiredScopes as $required) {
            if (!$scope->has($required)) {
                throw new TokenInvalidException(
                    'Token scope 不满足要求',
                    reason: sprintf('missing=%s actual=%s', $required, $scope->toString()),
                    jti: $payload->jti
                );
            }
        }
        return $this;
    }

    /**
     * 校验 scope 是否命中任一期望 scope
     *
     * @param Payload $payload
     * @param array<string> $anyScopes 命中其一即可
     * @return self
     * @throws TokenInvalidException
     */
    public function assertScopesAny(Payload $payload, array $anyScopes): self
    {
        if ($anyScopes === []) {
            return $this;
        }
        $scope = $this->extractScope($payload);
        if (!$scope->hasAny($anyScopes)) {
            throw new TokenInvalidException(
                'Token scope 不满足要求',
                reason: sprintf('expected_any=%s actual=%s', implode(',', $anyScopes), $scope->toString()),
                jti: $payload->jti
            );
        }
        return $this;
    }

    /**
     * 校验自定义声明等值匹配
     *
     * @param Payload $payload
     * @param string $key 自定义声明键名（位于 custom 数组）
     * @param mixed $expected 期望值（标量或可比较的数组）
     * @return self
     * @throws TokenInvalidException 当键缺失或值不匹配时
     */
    public function assertCustomEquals(Payload $payload, string $key, mixed $expected): self
    {
        if (!$payload->hasCustom($key)) {
            throw new TokenInvalidException(
                "Token 自定义声明缺失：{$key}",
                reason: "missing key={$key}",
                jti: $payload->jti
            );
        }
        $actual = $payload->getCustom($key);
        if (!$this->equals($expected, $actual)) {
            throw new TokenInvalidException(
                "Token 自定义声明不匹配：{$key}",
                reason: sprintf('expected=%s actual=%s', $this->dump($expected), $this->dump($actual)),
                jti: $payload->jti
            );
        }
        return $this;
    }

    /**
     * 校验 platform 严格匹配
     *
     * @param Payload $payload
     * @param string $expectedPlatform
     * @return self
     * @throws TokenInvalidException
     */
    public function assertPlatform(Payload $payload, string $expectedPlatform): self
    {
        if ($expectedPlatform === '' || $expectedPlatform === '*') {
            return $this;
        }
        if (!hash_equals($expectedPlatform, $payload->platform)) {
            throw new TokenInvalidException(
                'Token platform 不匹配',
                reason: sprintf('expected=%s actual=%s', $expectedPlatform, $payload->platform),
                jti: $payload->jti
            );
        }
        return $this;
    }

    /**
     * 从 Payload 提取 scope 并转为 Scope 值对象
     *
     * @param Payload $payload
     * @return Scope
     */
    public function extractScope(Payload $payload): Scope
    {
        $raw = $payload->custom['scope'] ?? null;
        if (is_string($raw)) {
            return Scope::fromString($raw);
        }
        if (is_array($raw)) {
            return Scope::fromArray($raw);
        }
        return new Scope([]);
    }

    /**
     * 严格相等比较（标量 + 数组）
     *
     * @param mixed $expected
     * @param mixed $actual
     * @return bool
     */
    private function equals(mixed $expected, mixed $actual): bool
    {
        if (is_array($expected) && is_array($actual)) {
            return $expected === $actual
                || (array_values($expected) === array_values($actual)
                    && empty(array_diff($expected, $actual)));
        }
        if (is_scalar($expected) && is_scalar($actual)) {
            return (string) $expected === (string) $actual;
        }
        return $expected === $actual;
    }

    /**
     * 调试用的值打印（截断长度）
     *
     * @param mixed $value
     * @return string
     */
    private function dump(mixed $value): string
    {
        if (is_array($value)) {
            try {
                $json = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                return substr((string) $json, 0, 80);
            } catch (\Throwable) {
                return '(array)';
            }
        }
        if (is_string($value)) {
            return substr($value, 0, 80);
        }
        if (is_scalar($value) || $value === null) {
            return var_export($value, true) ?: '(scalar)';
        }
        return '(' . get_debug_type($value) . ')';
    }
}
