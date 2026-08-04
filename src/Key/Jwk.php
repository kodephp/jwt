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
     * OKP（Ed25519/X25519）私钥参数名
     */
    private const array OKP_PRIVATE_PARAMS = ['d'];

    /**
     * oct 对称密钥参数名
     */
    private const array OCT_PRIVATE_PARAMS = ['k'];

    /**
     * 支持的密钥类型
     */
    private const array SUPPORTED_KTY = ['RSA', 'EC', 'OKP', 'oct'];

    /**
     * RFC 7638 §3.2 规定的指纹必需成员（按字典序）
     *
     * 计算指纹时只允许包含这些成员，且必须按字典序排列、无空白字符。
     */
    private const array THUMBPRINT_MEMBERS = [
        'RSA' => ['e', 'kty', 'n'],
        'EC' => ['crv', 'kty', 'x', 'y'],
        'OKP' => ['crv', 'kty', 'x'],
        'oct' => ['k', 'kty'],
    ];


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
            'OKP' => self::OKP_PRIVATE_PARAMS,
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
            'OKP' => self::OKP_PRIVATE_PARAMS,
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
        return $this->kty === 'RSA' || $this->kty === 'EC' || $this->kty === 'OKP';
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
     * 计算 JWK 指纹（RFC 7638）
     *
     * 与 computeKid() 的区别：指纹严格遵循 RFC 7638 的规范化规则，
     * 只取该密钥类型的必需成员、按字典序排列、无空白字符，
     * 因此跨语言、跨实现的计算结果完全一致，可直接用于：
     *  - DPoP 的 `jkt` 确认声明（RFC 9449）
     *  - 标准化的 kid 生成
     *  - 密钥去重与比对
     *
     * @param string $hash 摘要算法（sha256 / sha384 / sha512）
     * @return string base64url 编码的指纹
     * @throws JwtException 当缺少必需成员或摘要算法不支持时
     */
    public function thumbprint(string $hash = 'sha256'): string
    {
        if (!in_array($hash, ['sha256', 'sha384', 'sha512'], true)) {
            throw new JwtException("Unsupported thumbprint hash algorithm: {$hash}");
        }

        return self::base64UrlEncode(hash($hash, $this->canonicalThumbprintJson(), true));
    }

    /**
     * 计算 JWK 指纹 URI（RFC 9278）
     *
     * 形如 `urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8...`
     *
     * @param string $hash 摘要算法
     * @return string
     * @throws JwtException
     */
    public function thumbprintUri(string $hash = 'sha256'): string
    {
        $label = match ($hash) {
            'sha256' => 'sha-256',
            'sha384' => 'sha-384',
            'sha512' => 'sha-512',
            default => throw new JwtException("Unsupported thumbprint hash algorithm: {$hash}"),
        };

        return 'urn:ietf:params:oauth:jwk-thumbprint:' . $label . ':' . $this->thumbprint($hash);
    }

    /**
     * 生成 RFC 7638 规范化 JSON（指纹计算输入）
     *
     * @return string
     * @throws JwtException 当密钥缺少必需成员时
     */
    public function canonicalThumbprintJson(): string
    {
        $members = self::THUMBPRINT_MEMBERS[$this->kty] ?? null;
        if ($members === null) {
            throw new JwtException("Cannot compute thumbprint for kty: {$this->kty}");
        }

        $canonical = [];
        foreach ($members as $member) {
            if ($member === 'kty') {
                $canonical['kty'] = $this->kty;
                continue;
            }

            $value = $this->params[$member] ?? null;
            if ($value === null || $value === '') {
                throw new JwtException(
                    "JWK thumbprint requires \"{$member}\" for kty {$this->kty}"
                );
            }
            $canonical[$member] = (string) $value;
        }

        $json = json_encode($canonical, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new JwtException('Failed to build canonical JWK JSON: ' . json_last_error_msg());
        }

        return $json;
    }

    /**
     * 是否为 OKP（Ed25519 / X25519）密钥
     */
    public function isOkp(): bool
    {
        return $this->kty === 'OKP';
    }

    /**
     * 返回椭圆曲线名称（EC / OKP 专有）
     */
    public function getCurve(): ?string
    {
        $crv = $this->params['crv'] ?? null;
        return $crv === null ? null : (string) $crv;
    }

    /**
     * base64url 编码（RFC 7515 附录 C）
     */
    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
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
