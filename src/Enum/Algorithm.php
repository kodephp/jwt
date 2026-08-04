<?php

declare(strict_types=1);

namespace Kode\Jwt\Enum;

/**
 * JWS 签名算法枚举（RFC 7518 §3.1 + RFC 8037）
 *
 * 覆盖五大算法族：
 *  - HMAC（HS256/384/512）：对称密钥，性能最高
 *  - RSASSA-PKCS1-v1_5（RS256/384/512）：兼容性最好
 *  - ECDSA（ES256/384/512）：签名短、密钥小
 *  - RSASSA-PSS（PS256/384/512）：带盐随机化填充，安全性优于 PKCS1-v1_5
 *  - EdDSA（Ed25519）：现代曲线，确定性签名，需要 ext-sodium
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-3.1 RFC 7518 - JWA
 * @see https://datatracker.ietf.org/doc/html/rfc8037 RFC 8037 - CFRG Algorithms
 */
enum Algorithm: string
{
    case HS256 = 'HS256';
    case HS384 = 'HS384';
    case HS512 = 'HS512';
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';
    case PS256 = 'PS256';
    case PS384 = 'PS384';
    case PS512 = 'PS512';
    case EdDSA = 'EdDSA';

    public function isHmac(): bool
    {
        return match ($this) {
            self::HS256, self::HS384, self::HS512 => true,
            default => false,
        };
    }

    public function isRsa(): bool
    {
        return match ($this) {
            self::RS256, self::RS384, self::RS512 => true,
            default => false,
        };
    }

    public function isEcdsa(): bool
    {
        return match ($this) {
            self::ES256, self::ES384, self::ES512 => true,
            default => false,
        };
    }

    public function isRsapss(): bool
    {
        return match ($this) {
            self::PS256, self::PS384, self::PS512 => true,
            default => false,
        };
    }

    /**
     * 是否为 EdDSA（Ed25519）算法
     */
    public function isEddsa(): bool
    {
        return $this === self::EdDSA;
    }

    public function isAsymmetric(): bool
    {
        return $this->isRsa() || $this->isEcdsa() || $this->isRsapss() || $this->isEddsa();
    }

    /**
     * 算法族标识
     *
     * @return string HMAC / RSA / ECDSA / RSA-PSS / EdDSA
     */
    public function family(): string
    {
        return match (true) {
            $this->isHmac() => 'HMAC',
            $this->isRsa() => 'RSA',
            $this->isEcdsa() => 'ECDSA',
            $this->isRsapss() => 'RSA-PSS',
            default => 'EdDSA',
        };
    }

    /**
     * 对应的 PHP hash 摘要算法名
     *
     * EdDSA 内部固定使用 SHA-512，不需要外部指定摘要，返回 null。
     *
     * @return string|null sha256 / sha384 / sha512 / null
     */
    public function hashAlgorithm(): ?string
    {
        return match ($this) {
            self::HS256, self::RS256, self::ES256, self::PS256 => 'sha256',
            self::HS384, self::RS384, self::ES384, self::PS384 => 'sha384',
            self::HS512, self::RS512, self::ES512, self::PS512 => 'sha512',
            self::EdDSA => null,
        };
    }

    /**
     * 对应的 OpenSSL 摘要常量
     *
     * HMAC / EdDSA 不经由 openssl_sign，返回 null。
     */
    public function opensslAlgorithm(): ?int
    {
        if ($this->isHmac() || $this->isEddsa()) {
            return null;
        }

        return match ($this->hashAlgorithm()) {
            'sha256' => OPENSSL_ALGO_SHA256,
            'sha384' => OPENSSL_ALGO_SHA384,
            'sha512' => OPENSSL_ALGO_SHA512,
            default => null,
        };
    }

    /**
     * 椭圆曲线名称（JWK crv 参数）
     *
     * @return string|null P-256 / P-384 / P-521 / Ed25519，非 EC 类算法返回 null
     */
    public function curve(): ?string
    {
        return match ($this) {
            self::ES256 => 'P-256',
            self::ES384 => 'P-384',
            self::ES512 => 'P-521',
            self::EdDSA => 'Ed25519',
            default => null,
        };
    }

    /**
     * OpenSSL 曲线名称（用于 openssl_pkey_new）
     */
    public function opensslCurve(): ?string
    {
        return match ($this) {
            self::ES256 => 'prime256v1',
            self::ES384 => 'secp384r1',
            self::ES512 => 'secp521r1',
            default => null,
        };
    }

    /**
     * JOSE 规范中固定长度签名的字节数
     *
     * ECDSA 为 R||S 拼接（RFC 7518 §3.4），EdDSA 固定 64 字节。
     * RSA 家族签名长度取决于模数，返回 null。
     *
     * @return int|null
     */
    public function signatureLength(): ?int
    {
        return match ($this) {
            self::ES256 => 64,
            self::ES384 => 96,
            self::ES512 => 132,
            self::EdDSA => 64,
            default => null,
        };
    }

    /**
     * 该算法依赖的 PHP 扩展
     *
     * @return string|null 扩展名，无额外依赖返回 null
     */
    public function requiredExtension(): ?string
    {
        return match (true) {
            $this->isEddsa() => 'sodium',
            $this->isHmac() => null,
            default => 'openssl',
        };
    }

    /**
     * 当前运行环境是否支持该算法
     */
    public function isSupported(): bool
    {
        $extension = $this->requiredExtension();
        return $extension === null || extension_loaded($extension);
    }

    /**
     * 密钥/摘要强度（位）
     */
    public function getKeyBits(): int
    {
        return match ($this) {
            self::HS256, self::RS256, self::ES256, self::PS256, self::EdDSA => 256,
            self::HS384, self::RS384, self::ES384, self::PS384 => 384,
            self::HS512, self::RS512, self::ES512, self::PS512 => 512,
        };
    }

    /**
     * 大小写不敏感解析（EdDSA 在 JOSE 中为混合大小写，容易写错）
     *
     * @param string $value 算法字符串
     * @return static|null 无法识别时返回 null
     */
    public static function tryFromName(string $value): ?self
    {
        $normalized = strtoupper(trim($value));
        foreach (self::cases() as $case) {
            if (strtoupper($case->value) === $normalized) {
                return $case;
            }
        }
        return null;
    }

    /**
     * @return array<string>
     */
    public static function values(): array
    {
        return array_map(fn(self $case) => $case->value, self::cases());
    }

    /**
     * @return array<self>
     */
    public static function hmacAlgorithms(): array
    {
        return array_values(array_filter(
            self::cases(),
            fn(self $case) => $case->isHmac()
        ));
    }

    /**
     * @return array<self>
     */
    public static function asymmetricAlgorithms(): array
    {
        return array_values(array_filter(
            self::cases(),
            fn(self $case) => $case->isAsymmetric()
        ));
    }

    /**
     * 当前环境实际可用的算法列表
     *
     * @return array<self>
     */
    public static function supportedAlgorithms(): array
    {
        return array_values(array_filter(
            self::cases(),
            fn(self $case) => $case->isSupported()
        ));
    }
}
