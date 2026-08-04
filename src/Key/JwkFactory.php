<?php

declare(strict_types=1);

namespace Kode\Jwt\Key;

use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Signature\Ed25519;

/**
 * JWK 密钥生成工厂
 *
 * 提供安全的密钥生成能力，使用密码学安全的随机数生成器（CSPRNG）。
 * 适用于密钥初始化、密钥轮换、密钥迁移等场景。
 *
 * 安全说明：
 *  - 所有随机数使用 random_bytes()（CSPRNG），不使用 mt_rand/rand 等不安全源
 *  - RSA 密钥对生成默认 2048 位，最低 2048 位（NIST 建议）
 *  - 对称密钥长度根据算法自动选择（HS256=32字节、HS384=48字节、HS512=64字节）
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7518 RFC 7518 - JSON Web Algorithms
 */
final class JwkFactory
{
    /**
     * 各算法所需密钥字节数
     */
    private const array ALG_KEY_BYTES = [
        'HS256' => 32,
        'HS384' => 48,
        'HS512' => 64,
    ];

    /**
     * 生成对称密钥 (oct) JWK
     *
     * @param string $alg 算法（HS256/HS384/HS512），决定密钥长度
     * @param string|null $kid 密钥标识，未指定时自动生成
     * @return Jwk
     * @throws JwtException 当算法不支持时
     */
    public static function generateOctKey(string $alg = 'HS256', ?string $kid = null): Jwk
    {
        $algUpper = strtoupper($alg);
        if (!isset(self::ALG_KEY_BYTES[$algUpper])) {
            $supported = implode(', ', array_keys(self::ALG_KEY_BYTES));
            throw new JwtException("Unsupported symmetric algorithm: {$alg}. Supported: {$supported}");
        }

        $bytes = random_bytes(self::ALG_KEY_BYTES[$algUpper]);
        $kid ??= self::generateKid('oct');

        return Jwk::create(
            kty: 'oct',
            params: ['k' => self::base64UrlEncode($bytes)],
            use: 'sig',
            alg: $algUpper,
            kid: $kid,
        );
    }

    /**
     * 生成 RSA 密钥对
     *
     * 返回包含 private 和 public 两个 JWK 的数组。
     * public JWK 可安全分发给验证方，private JWK 用于签发。
     *
     * @param int $bits 密钥位数（默认 2048，最低 2048）
     * @param string|null $alg 适用的算法（RS256/RS384/RS512/PS256 等）
     * @param string|null $kid 密钥标识
     * @return array{private: Jwk, public: Jwk}
     * @throws JwtException 当位数不足或生成失败时
     */
    public static function generateRsaKeyPair(int $bits = 2048, ?string $alg = 'RS256', ?string $kid = null): array
    {
        // NIST SP 800-131A：RSA 密钥长度不得低于 2048 位
        if ($bits < 2048) {
            throw new JwtException('RSA key size must be at least 2048 bits per NIST SP 800-131A');
        }

        $config = [
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        $keyResource = openssl_pkey_new($config);
        if ($keyResource === false) {
            throw new JwtException('Failed to generate RSA key pair: ' . self::lastSslError());
        }

        // 导出 PEM 格式私钥
        $privatePem = '';
        if (!openssl_pkey_export($keyResource, $privatePem)) {
            throw new JwtException('Failed to export RSA private key');
        }

        $kid ??= self::generateKid('RSA');
        $private = KeyConverter::rsaPrivateKeyToJwk($privatePem, $kid, $alg);
        $public = $private->toPublic();

        return ['private' => $private, 'public' => $public];
    }

    /**
     * 生成 EC 密钥对（P-256 / P-384 / P-521）
     *
     * @param string $curve JWK 曲线名（P-256 / P-384 / P-521）
     * @param string|null $kid 密钥标识
     * @return array{private: Jwk, public: Jwk}
     * @throws JwtException 当曲线不受支持或生成失败时
     */
    public static function generateEcKeyPair(string $curve = 'P-256', ?string $kid = null): array
    {
        $map = [
            'P-256' => ['prime256v1', 'ES256'],
            'P-384' => ['secp384r1', 'ES384'],
            'P-521' => ['secp521r1', 'ES512'],
        ];

        if (!isset($map[$curve])) {
            throw new JwtException(
                "Unsupported EC curve: {$curve}. Supported: " . implode(', ', array_keys($map))
            );
        }

        [$opensslCurve, $alg] = $map[$curve];

        $keyResource = openssl_pkey_new([
            'curve_name' => $opensslCurve,
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        if ($keyResource === false) {
            throw new JwtException('Failed to generate EC key pair: ' . self::lastSslError());
        }

        $privatePem = '';
        if (!openssl_pkey_export($keyResource, $privatePem)) {
            throw new JwtException('Failed to export EC private key');
        }

        $kid ??= self::generateKid('EC');
        $private = KeyConverter::ecPrivateKeyToJwk($privatePem, $kid, $alg);

        return ['private' => $private, 'public' => $private->toPublic()];
    }

    /**
     * 生成 Ed25519（OKP）密钥对
     *
     * @param string|null $kid 密钥标识
     * @return array{private: Jwk, public: Jwk}
     * @throws JwtException 当 sodium 扩展缺失时
     */
    public static function generateEd25519KeyPair(?string $kid = null): array
    {
        $pair = Ed25519::generateKeyPair();
        $kid ??= self::generateKid('OKP');

        $private = Jwk::create(
            kty: 'OKP',
            params: [
                'crv' => 'Ed25519',
                'x' => self::base64UrlEncode($pair['publicRaw']),
                'd' => self::base64UrlEncode($pair['seed']),
            ],
            use: 'sig',
            alg: 'EdDSA',
            kid: $kid,
        );

        return ['private' => $private, 'public' => $private->toPublic()];
    }

    /**
     * 生成密钥标识 kid
     *
     * 使用 8 字节密码学安全随机数，编码为 16 位十六进制字符串。
     *
     * @param string $prefix 前缀（如 oct/RSA）
     * @return string 形如 "oct-a1b2c3d4e5f6a7b8"
     */
    public static function generateKid(string $prefix = 'key'): string
    {
        return $prefix . '-' . bin2hex(random_bytes(8));
    }

    /**
     * 从现有对称密钥创建 JWK（便捷方法）
     *
     * @param string $secret 原始密钥
     * @param string $alg 算法
     * @param string|null $kid
     * @return Jwk
     */
    public static function fromSecret(string $secret, string $alg = 'HS256', ?string $kid = null): Jwk
    {
        return KeyConverter::octToJwk($secret, $kid ?? self::generateKid('oct'), $alg);
    }

    /**
     * 从 PEM 创建 JWK（自动识别密钥类型与公私钥）
     *
     * 支持 RSA、EC（P-256/P-384/P-521）与 Ed25519（OKP）。
     *
     * @param string $pem PEM 字符串或文件路径
     * @param string|null $kid
     * @param string|null $alg
     * @return Jwk
     * @throws JwtException 当 PEM 既非公钥也非私钥时
     */
    public static function fromPem(string $pem, ?string $kid = null, ?string $alg = null): Jwk
    {
        $content = is_file($pem) ? (string) file_get_contents($pem) : $pem;

        // Ed25519 无法通过 openssl_pkey_get_details 取得原始坐标，单独识别
        if (self::isEd25519Pem($content)) {
            return str_contains($content, 'PRIVATE KEY')
                ? KeyConverter::ed25519PrivateKeyToJwk($content, $kid ?? self::generateKid('OKP'))
                : KeyConverter::ed25519PublicKeyToJwk($content, $kid ?? self::generateKid('OKP'));
        }

        // 优先尝试作为私钥加载（私钥通常包含公钥信息）
        $privateKey = @openssl_pkey_get_private($content);
        if ($privateKey !== false) {
            $type = (int) (openssl_pkey_get_details($privateKey)['type'] ?? -1);
            return $type === OPENSSL_KEYTYPE_EC
                ? KeyConverter::ecPrivateKeyToJwk($content, $kid ?? self::generateKid('EC'), $alg)
                : KeyConverter::rsaPrivateKeyToJwk($content, $kid ?? self::generateKid('RSA'), $alg);
        }

        // 退化为公钥
        $publicKey = @openssl_pkey_get_public($content);
        if ($publicKey !== false) {
            $type = (int) (openssl_pkey_get_details($publicKey)['type'] ?? -1);
            return $type === OPENSSL_KEYTYPE_EC
                ? KeyConverter::ecPublicKeyToJwk($content, $kid ?? self::generateKid('EC'), $alg)
                : KeyConverter::rsaPublicKeyToJwk($content, $kid ?? self::generateKid('RSA'), $alg);
        }

        throw new JwtException('PEM is neither a valid private key nor a public key');
    }

    /**
     * 判断 PEM 是否为 Ed25519 密钥
     */
    private static function isEd25519Pem(string $pem): bool
    {
        try {
            if (str_contains($pem, 'PRIVATE KEY')) {
                Ed25519::pemToSeed($pem);
                return true;
            }
            if (str_contains($pem, 'PUBLIC KEY')) {
                Ed25519::pemToPublicKey($pem);
                return true;
            }
        } catch (JwtException) {
            return false;
        }

        return false;
    }

    /**
     * base64url 编码
     */
    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * 获取最后一个 OpenSSL 错误
     */
    private static function lastSslError(): string
    {
        $message = '';
        while ($error = openssl_error_string()) {
            $message = $error;
        }
        return $message === '' ? 'unknown error' : $message;
    }
}
