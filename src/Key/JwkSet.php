<?php

declare(strict_types=1);

namespace Kode\Jwt\Key;

use Kode\Jwt\Contract\Arrayable;
use Kode\Jwt\Contract\Jsonable;
use Kode\Jwt\Exception\JwtException;

/**
 * JSON Web Key Set (JWK Set) 集合
 *
 * 表示一组 JWK 的集合，符合 RFC 7517 Section 5。
 * 主要用于密钥轮换场景：验证方持有多个公钥，根据 Token header 中的 kid 选择对应公钥验签。
 *
 * 安全设计：
 *  - 不可变集合（readonly class），添加/移除密钥返回新实例
 *  - 通过 kid 选择密钥时，找不到则抛出异常（而非静默返回 null）
 *  - toJson() 默认输出公钥集合，避免误将私钥集合分发给验证方
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7517#section-5 RFC 7517 Section 5 - JWK Set
 */
final readonly class JwkSet implements Arrayable, Jsonable
{
    /**
     * @param array<string, Jwk> $jwks 以 kid 为键的 JWK 映射；kid 缺失时使用自增索引
     */
    public function __construct(public array $jwks = [])
    {
    }

    /**
     * 从 JWK 数组构造集合
     *
     * @param array<Jwk|array<string, mixed>> $jwks JWK 对象数组或参数数组
     * @return static
     */
    public static function fromArray(array $jwks): static
    {
        $map = [];
        $index = 0;
        foreach ($jwks as $item) {
            $jwk = $item instanceof Jwk ? $item : Jwk::fromArray($item);
            $kid = $jwk->getKid() ?? (string) $index++;
            $map[$kid] = $jwk;
        }
        return new static($map);
    }

    /**
     * 从 JSON 字符串构造集合
     *
     * @param string $json {"keys": [...]} 格式的 JWK Set JSON
     * @return static
     * @throws JwtException 当 JSON 解析失败时
     */
    public static function fromJson(string $json): static
    {
        if (!json_validate($json)) {
            throw new JwtException('Invalid JWK Set JSON: ' . json_last_error_msg());
        }
        $data = json_decode($json, true);
        if (!is_array($data) || !isset($data['keys']) || !is_array($data['keys'])) {
            throw new JwtException('JWK Set JSON must contain "keys" array');
        }
        return self::fromArray($data['keys']);
    }

    /**
     * 根据 kid 选择密钥
     *
     * @param string $kid 密钥标识
     * @return Jwk
     * @throws JwtException 当 kid 不存在时
     */
    public function get(string $kid): Jwk
    {
        if (!isset($this->jwks[$kid])) {
            throw new JwtException("JWK not found for kid: {$kid}");
        }
        return $this->jwks[$kid];
    }

    /**
     * 根据 alg 选择第一个匹配算法的密钥
     *
     * @param string $alg 算法标识（如 RS256）
     * @return Jwk|null 不存在时返回 null
     */
    public function findByAlgorithm(string $alg): ?Jwk
    {
        foreach ($this->jwks as $jwk) {
            if ($jwk->getAlg() === $alg) {
                return $jwk;
            }
        }
        return null;
    }

    /**
     * 添加 JWK，返回新集合（不可变）
     *
     * @param Jwk $jwk
     * @return static
     */
    public function with(Jwk $jwk): static
    {
        $kid = $jwk->getKid() ?? (string) count($this->jwks);
        return new static(array_merge($this->jwks, [$kid => $jwk]));
    }

    /**
     * 移除指定 kid 的 JWK，返回新集合（不可变）
     *
     * @param string $kid
     * @return static
     */
    public function without(string $kid): static
    {
        $new = $this->jwks;
        unset($new[$kid]);
        return new static($new);
    }

    /**
     * 集合中是否存在指定 kid
     *
     * @param string $kid
     * @return bool
     */
    public function has(string $kid): bool
    {
        return isset($this->jwks[$kid]);
    }

    /**
     * 密钥数量
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->jwks);
    }

    /**
     * 转为数组（含私钥参数，请勿公开分发）
     *
     * @return array<string, mixed> {"keys": [...]}
     */
    #[\Override]
    public function toArray(): array
    {
        return ['keys' => array_values(array_map(fn(Jwk $jwk) => $jwk->toArray(), $this->jwks))];
    }

    /**
     * 转为 JSON 字符串（含私钥参数，请勿公开分发）
     *
     * @param int $options json_encode 选项
     * @return string
     */
    #[\Override]
    public function toJson(int $options = 0): string
    {
        $options = $options | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        $json = json_encode($this->toArray(), $options);
        if ($json === false) {
            throw new JwtException('Failed to encode JWK Set to JSON: ' . json_last_error_msg());
        }
        return $json;
    }

    /**
     * 转为公开 JWK Set（所有 JWK 均剥离私钥参数）
     *
     * 用于将公钥集合安全分发给 Token 验证方。
     *
     * @return static 新的 JwkSet 实例
     */
    public function toPublic(): static
    {
        return new static(array_map(fn(Jwk $jwk) => $jwk->toPublic(), $this->jwks));
    }
}
