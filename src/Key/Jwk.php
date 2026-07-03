<?php

declare(strict_types=1);

namespace Kode\Jwt\Key;

use Kode\Jwt\Contract\Arrayable;
use Kode\Jwt\Contract\Jsonable;
use Kode\Jwt\Exception\JwtException;
use Stringable;

/**
 * JSON Web Key (JWK) 值对象
 *
 * 表示一个符合 RFC 7517 标准的密钥。支持 RSA、EC、oct（对称）三种密钥类型。
 * 使用 PHP 8.3+ 的 readonly class 保证不可变性，避免密钥在传递中被篡改。
 *
 * 安全设计：
 *  - 私钥参数（d、p、q、dp、dq、qi、k）仅在显式调用 toArray() 时输出
 *  - toPublic() 返回剥离私钥参数的公开 JWK，可安全分发给验证方
 *  - 通过 __toString() 不会泄露密钥内容
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7517 RFC 7517 - JSON Web Key
 * @see https://datatracker.ietf.org/doc/html/rfc7518 RFC 7518 - JSON Web Algorithms
 */
final readonly class Jwk implements Arrayable, Jsonable, Stringable
{
    /**
     * RSA 私钥参数名（toPublic 时需剥离）
     */
    private const array RSA_PRIVATE_PARAMS = ['d', 'p', 'q', 'dp', 'dq', 'qi'];

    /**
     * EC 私钥参数名
     */
    private const array EC_PRIVATE_PARAMS = ['d'];

    /**
     * oct 对称密钥参数名
     */
    private const array OCT_PRIVATE_PARAMS = ['k'];

    /**
     * 支持的密钥类型
     */
    private const array SUPPORTED_KTY = ['RSA', 'EC', 'oct'];


    /**
     * 私有构造函数，请通过静态工厂方法 create() / fromArray() / fromJson() 创建实例。
     *
     * @param string $kty 密钥类型（必须已归一化：RSA / EC / oct）
     * @param array<string, mixed> $params 密钥参数（如 n/e/d/x/y/crv/k 等）
     * @param string|null $use 公钥用途（sig 签名 / enc 加密）
     * @param array<string>|null $keyOps 允许的操作列表（sign/verify/encrypt/decrypt/wrapKey/unwrapKey）
     * @param string|null $alg 该密钥适用的算法（如 RS256、ES256、HS256）
     * @param string|null $kid 密钥标识，用于在 JWK Set 中选择密钥
     */
    private function __construct(
        public string $kty,
        public array $params = [],
        public ?string $use = null,
        public ?array $keyOps = null,
        public ?string $alg = null,
        public ?string $kid = null,
    ) {
        // kty 已由 create() 归一化，这里仅做防御性校验
        if (!in_array($kty, self::SUPPORTED_KTY, true)) {
            throw new JwtException("Unsupported JWK kty: {$kty}. Supported: " . implode(', ', self::SUPPORTED_KTY));
        }
    }

    /**
     * 静态工厂方法（推荐入口）
     *
     * 自动将 kty 归一化为首字母大写形式（rsa → RSA），避免 readonly 限制下无法在构造函数内修改属性。
     *
     * @param string $kty 密钥类型（大小写不敏感：rsa/RSA/Rsa 均可）
     * @param array<string, mixed> $params 密钥参数
     * @param string|null $use 公钥用途
     * @param array<string>|null $keyOps 允许的操作列表
     * @param string|null $alg 适用的算法
     * @param string|null $kid 密钥标识
     * @return static
     */
    public static function create(
        string $kty,
        array $params = [],
        ?string $use = null,
        ?array $keyOps = null,
        ?string $alg = null,
        ?string $kid = null,
    ): static {
        $normalized = self::normalizeKty($kty);
        return new static($normalized, $params, $use, $keyOps, $alg, $kid);
    }

    /**
     * 归一化 kty
     *
     * RFC 7518 规定：RSA/EC 全大写，oct 全小写（特殊保留字）。
     * 输入大小写不敏感，但输出必须严格符合规范。
     */
    private static function normalizeKty(string $kty): string
    {
        $lower = strtolower($kty);
        // oct 是 JWK 规范中唯一全小写的 kty，特殊处理
        if ($lower === 'oct') {
            return 'oct';
        }
        // 其余类型（RSA/EC）全大写
        return strtoupper($kty);
    }

    /**
     * 从数组构造 JWK
     *
     * @param array<string, mixed> $data JWK 参数数组，必须包含 kty
     * @return static
     * @throws JwtException 当缺少 kty 字段时
     */
    public static function fromArray(array $data): static
    {
        $kty = (string) ($data['kty'] ?? '');
        if ($kty === '') {
            throw new JwtException('JWK requires "kty" field');
        }

        // 提取参数（排除元数据字段）
        $metaKeys = ['kty', 'use', 'key_ops', 'alg', 'kid'];
        $params = array_filter(
            $data,
            fn($key) => !in_array($key, $metaKeys, true),
            ARRAY_FILTER_USE_KEY
        );

        return self::create(
            kty: $kty,
            params: $params,
            use: isset($data['use']) ? (string) $data['use'] : null,
            keyOps: isset($data['key_ops']) && is_array($data['key_ops']) ? $data['key_ops'] : null,
            alg: isset($data['alg']) ? (string) $data['alg'] : null,
            kid: isset($data['kid']) ? (string) $data['kid'] : null,
        );
    }

    /**
     * 从 JSON 字符串构造 JWK
     *
     * @param string $json 符合 RFC 7517 的 JWK JSON
     * @return static
     * @throws JwtException 当 JSON 解析失败或缺少 kty 时
     */
    public static function fromJson(string $json): static
    {
        if (!json_validate($json)) {
            throw new JwtException('Invalid JWK JSON: ' . json_last_error_msg());
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new JwtException('JWK JSON must be an object');
        }
        return self::fromArray($data);
    }

    /**
     * 转为关联数组（含私钥参数，请勿公开分发）
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function toArray(): array
    {
        $result = ['kty' => $this->kty];

        // 参数按键名排序输出，保证可重现性
        $params = $this->params;
        ksort($params);
        foreach ($params as $key => $value) {
            $result[$key] = $value;
        }

        if ($this->use !== null) {
            $result['use'] = $this->use;
        }
        if ($this->keyOps !== null) {
            $result['key_ops'] = $this->keyOps;
        }
        if ($this->alg !== null) {
            $result['alg'] = $this->alg;
        }
        if ($this->kid !== null) {
            $result['kid'] = $this->kid;
        }

        return $result;
    }

    /**
     * 转为 JSON 字符串（含私钥参数，请勿公开分发）
     *
     * @param int $options json_encode 选项，默认使用紧凑无转义输出
     * @return string
     */
    #[\Override]
    public function toJson(int $options = 0): string
    {
        $options = $options | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        $json = json_encode($this->toArray(), $options);
        if ($json === false) {
            throw new JwtException('Failed to encode JWK to JSON: ' . json_last_error_msg());
        }
        return $json;
    }

    /**
     * 转为公开 JWK（剥离所有私钥参数）
     *
     * 用于将公钥安全分发给 Token 验证方。
     *
     * @return static 新的 JWK 实例（不可变，返回新对象）
     */
    public function toPublic(): static
    {
        $privateParams = match ($this->kty) {
            'RSA' => self::RSA_PRIVATE_PARAMS,
            'EC' => self::EC_PRIVATE_PARAMS,
            'oct' => self::OCT_PRIVATE_PARAMS,
            default => [],
        };

        $publicParams = array_filter(
            $this->params,
            fn($key) => !in_array($key, $privateParams, true),
            ARRAY_FILTER_USE_KEY
        );

        return new static(
            kty: $this->kty,
            params: $publicParams,
            use: $this->use,
            keyOps: $this->keyOps,
            alg: $this->alg,
            kid: $this->kid,
        );
    }

    /**
     * 判断是否为私钥（包含私钥参数）
     *
     * @return bool
     */
    public function isPrivate(): bool
    {
        $privateParams = match ($this->kty) {
            'RSA' => self::RSA_PRIVATE_PARAMS,
            'EC' => self::EC_PRIVATE_PARAMS,
            'oct' => self::OCT_PRIVATE_PARAMS,
            default => [],
        };

        foreach ($privateParams as $param) {
            if (isset($this->params[$param])) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断是否为对称密钥（oct）
     *
     * @return bool
     */
    public function isSymmetric(): bool
    {
        return $this->kty === 'oct';
    }

    /**
     * 判断是否为非对称密钥（RSA / EC）
     *
     * @return bool
     */
    public function isAsymmetric(): bool
    {
        return $this->kty === 'RSA' || $this->kty === 'EC';
    }

    /**
     * 获取指定参数
     *
     * @param string $name 参数名（如 n、e、d、x、y、crv、k）
     * @return mixed 参数值，不存在时返回 null
     */
    public function getParam(string $name): mixed
    {
        return $this->params[$name] ?? null;
    }

    /**
     * 是否包含指定参数
     *
     * @param string $name 参数名
     * @return bool
     */
    public function hasParam(string $name): bool
    {
        return array_key_exists($name, $this->params);
    }

    /**
     * 返回密钥标识 kid
     *
     * @return string|null
     */
    public function getKid(): ?string
    {
        return $this->kid;
    }

    /**
     * 返回密钥类型 kty
     *
     * @return string
     */
    public function getKty(): string
    {
        return $this->kty;
    }

    /**
     * 返回该密钥适用的算法 alg
     *
     * @return string|null
     */
    public function getAlg(): ?string
    {
        return $this->alg;
    }

    /**
     * 计算 kid（基于公钥参数的 SHA-256 指纹）
     *
     * 当 JWK 未显式设置 kid 时，可通过此方法生成确定性 kid，
     * 用于 JWK Set 中的密钥选择。
     *
     * @return string 8 字节短哈希（16 个十六进制字符）
     */
    public function computeKid(): string
    {
        $public = $this->toPublic();
        $canonical = json_encode($public->toArray(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return substr(hash('sha256', (string) $canonical), 0, 16);
    }

    /**
     * 返回脱敏的字符串表示（不泄露密钥内容）
     *
     * @return string
     */
    #[\Override]
    public function __toString(): string
    {
        $private = $this->isPrivate() ? 'yes' : 'no';
        $kid = $this->kid ?? '?';
        $alg = $this->alg ?? '?';
        return sprintf('Jwk(kty=%s, kid=%s, alg=%s, private=%s)', $this->kty, $kid, $alg, $private);
    }
}
