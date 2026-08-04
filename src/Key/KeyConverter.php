<?php

declare(strict_types=1);

namespace Kode\Jwt\Key;

use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Signature\Ed25519;

/**
 * 密钥格式转换器
 *
 * 在 PEM 格式（OpenSSL 原生）与 JWK 格式（RFC 7517）之间互转，
 * 让现有 PEM 密钥基础设施能无缝接入 JWK 工作流。
 *
 * 支持的转换：
 *  - RSA 公钥 / 私钥 PEM ↔ JWK（n/e 与完整私钥参数）
 *  - EC 公钥 / 私钥 PEM ↔ JWK（P-256 / P-384 / P-521 的 x/y/d 坐标）
 *  - OKP（Ed25519）公钥 / 私钥 PEM ↔ JWK（RFC 8037 的 x/d）
 *  - 对称密钥 ↔ JWK（oct）
 *
 * 安全说明：
 *  - 私钥参数仅在显式调用私钥转换方法时输出，公钥转换绝不携带私钥材料
 *  - 所有 base64 编解码均使用 URL-safe 字符集（RFC 7515）
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-6.3 RFC 7518 JWK 参数
 * @see https://datatracker.ietf.org/doc/html/rfc8037 RFC 8037 OKP 密钥类型
 */
final class KeyConverter
{
    /**
     * JWK crv → OpenSSL 曲线名
     */
    private const array CURVE_MAP = [
        'P-256' => 'prime256v1',
        'P-384' => 'secp384r1',
        'P-521' => 'secp521r1',
    ];

    /**
     * JWK crv → 坐标字节长度
     */
    private const array CURVE_SIZE = [
        'P-256' => 32,
        'P-384' => 48,
        'P-521' => 66,
    ];

    /**
     * JWK crv → 命名曲线 OID 的 DER 编码
     */
    private const array CURVE_OID = [
        'P-256' => "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        'P-384' => "\x06\x05\x2b\x81\x04\x00\x22",
        'P-521' => "\x06\x05\x2b\x81\x04\x00\x23",
    ];

    /**
     * RSA 公钥 PEM → JWK
     *
     * @param string $pem PEM 格式公钥（可为文件路径或 PEM 字符串）
     * @param string|null $kid 密钥标识
     * @param string|null $alg 适用的算法（如 RS256）
     * @return Jwk
     * @throws JwtException 当 PEM 无效时
     */
    public static function rsaPublicKeyToJwk(string $pem, ?string $kid = null, ?string $alg = null): Jwk
    {
        $key = self::loadPublicKey($pem);
        $details = openssl_pkey_get_details($key);

        if ($details === false || ($details['type'] ?? 0) !== OPENSSL_KEYTYPE_RSA) {
            throw new JwtException('Invalid RSA public key: not an RSA key or details unavailable');
        }

        $n = self::base64UrlEncode($details['rsa']['n']);
        $e = self::base64UrlEncode($details['rsa']['e']);

        return Jwk::create(
            kty: 'RSA',
            params: ['n' => $n, 'e' => $e],
            use: 'sig',
            alg: $alg,
            kid: $kid,
        );
    }

    /**
     * RSA 私钥 PEM → JWK
     *
     * 包含完整私钥参数（d/p/q/dp/dq/qi），请勿公开分发。
     *
     * @param string $pem PEM 格式私钥（可为文件路径或 PEM 字符串）
     * @param string|null $kid 密钥标识
     * @param string|null $alg 适用的算法
     * @return Jwk
     * @throws JwtException 当 PEM 无效时
     */
    public static function rsaPrivateKeyToJwk(string $pem, ?string $kid = null, ?string $alg = null): Jwk
    {
        $key = self::loadPrivateKey($pem);
        $details = openssl_pkey_get_details($key);

        if ($details === false || ($details['type'] ?? 0) !== OPENSSL_KEYTYPE_RSA) {
            throw new JwtException('Invalid RSA private key: not an RSA key or details unavailable');
        }

        $rsa = $details['rsa'];
        $params = [
            'n' => self::base64UrlEncode($rsa['n']),
            'e' => self::base64UrlEncode($rsa['e']),
            'd' => self::base64UrlEncode($rsa['d']),
            'p' => self::base64UrlEncode($rsa['p']),
            'q' => self::base64UrlEncode($rsa['q']),
            'dp' => self::base64UrlEncode($rsa['dmp1']),
            'dq' => self::base64UrlEncode($rsa['dmq1']),
            'qi' => self::base64UrlEncode($rsa['iqmp']),
        ];

        return Jwk::create(
            kty: 'RSA',
            params: $params,
            use: 'sig',
            alg: $alg,
            kid: $kid,
        );
    }

    /**
     * EC 公钥 PEM → JWK
     *
     * @param string $pem PEM 格式公钥或文件路径
     * @param string|null $kid 密钥标识
     * @param string|null $alg 适用算法（如 ES256）
     * @return Jwk
     * @throws JwtException 当 PEM 不是 EC 公钥或曲线不受支持时
     */
    public static function ecPublicKeyToJwk(string $pem, ?string $kid = null, ?string $alg = null): Jwk
    {
        $details = self::ecDetails(self::loadPublicKey($pem));
        $crv = self::curveNameToJwk((string) ($details['curve_name'] ?? ''));
        $size = self::CURVE_SIZE[$crv];

        return Jwk::create(
            kty: 'EC',
            params: [
                'crv' => $crv,
                'x' => self::base64UrlEncode(self::padCoordinate((string) $details['x'], $size)),
                'y' => self::base64UrlEncode(self::padCoordinate((string) $details['y'], $size)),
            ],
            use: 'sig',
            alg: $alg,
            kid: $kid,
        );
    }

    /**
     * EC 私钥 PEM → JWK（含 d 参数，请勿公开分发）
     *
     * @throws JwtException
     */
    public static function ecPrivateKeyToJwk(string $pem, ?string $kid = null, ?string $alg = null): Jwk
    {
        $details = self::ecDetails(self::loadPrivateKey($pem));
        $crv = self::curveNameToJwk((string) ($details['curve_name'] ?? ''));
        $size = self::CURVE_SIZE[$crv];

        if (!isset($details['d'])) {
            throw new JwtException('EC PEM does not contain a private key component');
        }

        return Jwk::create(
            kty: 'EC',
            params: [
                'crv' => $crv,
                'x' => self::base64UrlEncode(self::padCoordinate((string) $details['x'], $size)),
                'y' => self::base64UrlEncode(self::padCoordinate((string) $details['y'], $size)),
                'd' => self::base64UrlEncode(self::padCoordinate((string) $details['d'], $size)),
            ],
            use: 'sig',
            alg: $alg,
            kid: $kid,
        );
    }

    /**
     * Ed25519 公钥 PEM → OKP JWK（RFC 8037）
     *
     * @throws JwtException
     */
    public static function ed25519PublicKeyToJwk(string $pem, ?string $kid = null): Jwk
    {
        $raw = Ed25519::pemToPublicKey($pem);

        return Jwk::create(
            kty: 'OKP',
            params: ['crv' => 'Ed25519', 'x' => self::base64UrlEncode($raw)],
            use: 'sig',
            alg: 'EdDSA',
            kid: $kid,
        );
    }

    /**
     * Ed25519 私钥 PEM → OKP JWK（含 d 参数）
     *
     * @throws JwtException
     */
    public static function ed25519PrivateKeyToJwk(string $pem, ?string $kid = null): Jwk
    {
        $seed = Ed25519::pemToSeed($pem);
        $public = Ed25519::publicKeyFromSeed($seed);

        return Jwk::create(
            kty: 'OKP',
            params: [
                'crv' => 'Ed25519',
                'x' => self::base64UrlEncode($public),
                'd' => self::base64UrlEncode($seed),
            ],
            use: 'sig',
            alg: 'EdDSA',
            kid: $kid,
        );
    }

    /**
     * JWK 私钥 → PEM 私钥
     *
     * 目前支持 EC（P-256/P-384/P-521）与 OKP（Ed25519）。
     * RSA 私钥请直接使用原始 PEM，避免在应用层重组 CRT 参数。
     *
     * @throws JwtException
     */
    public static function jwkToPrivatePem(Jwk $jwk): string
    {
        if (!$jwk->isPrivate()) {
            throw new JwtException('JWK does not contain private key material');
        }

        return match ($jwk->getKty()) {
            'OKP' => Ed25519::seedToPem(self::base64UrlDecode((string) $jwk->getParam('d'))),
            'EC' => self::ecJwkToPrivatePem($jwk),
            default => throw new JwtException(
                "Private PEM export is not supported for kty: {$jwk->getKty()}"
            ),
        };
    }

    /**
     * JWK → PEM（公钥）
     *
     * 支持 RSA（n/e）、EC（crv/x/y）、OKP（Ed25519 的 x）。
     * 传入私钥 JWK 时会自动剥离私钥参数，仅导出公钥部分。
     *
     * @param Jwk $jwk
     * @return string PEM 格式公钥
     * @throws JwtException 当 JWK 类型不支持或参数缺失时
     */
    public static function jwkToPem(Jwk $jwk): string
    {
        $kty = $jwk->getKty();

        if ($kty === 'EC') {
            return self::ecJwkToPem($jwk->isPrivate() ? $jwk->toPublic() : $jwk);
        }

        if ($kty === 'OKP') {
            $x = $jwk->getParam('x');
            if ($x === null) {
                throw new JwtException('OKP JWK requires "x" parameter');
            }
            return Ed25519::publicKeyToPem(self::base64UrlDecode((string) $x));
        }

        if ($kty !== 'RSA') {
            throw new JwtException("JWK of kty {$kty} cannot be converted to PEM");
        }

        if ($jwk->isPrivate()) {
            throw new JwtException(
                'Cannot convert private JWK to PEM; use toPublic() first or load via openssl directly'
            );
        }

        $n = $jwk->getParam('n');
        $e = $jwk->getParam('e');
        if ($n === null || $e === null) {
            throw new JwtException('RSA public JWK requires "n" and "e" parameters');
        }

        $nBin = self::base64UrlDecode($n);
        $eBin = self::base64UrlDecode($e);

        // 构造 ASN.1 DER 编码的 RSA 公钥（SubjectPublicKeyInfo）
        $modulus = self::encodeAsn1Integer($nBin);
        $exponent = self::encodeAsn1Integer($eBin);
        $rsaPublicKey = self::encodeAsn1Sequence($modulus . $exponent);

        // SubjectPublicKeyInfo 包装
        $algorithm = self::encodeAsn1Sequence("\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" . "\x05\x00");
        $subjectPublicKeyInfo = self::encodeAsn1Sequence($algorithm . self::encodeAsn1BitString($rsaPublicKey));

        $pem = "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n") .
            "-----END PUBLIC KEY-----\n";

        // 验证生成的 PEM 可被 OpenSSL 解析
        if (openssl_pkey_get_public($pem) === false) {
            throw new JwtException('Failed to construct valid PEM from JWK');
        }

        return $pem;
    }

    /**
     * 对称密钥 → JWK (oct)
     *
     * @param string $secret 原始密钥字节
     * @param string|null $kid
     * @param string|null $alg 适用的算法（如 HS256）
     * @return Jwk
     */
    public static function octToJwk(string $secret, ?string $kid = null, ?string $alg = null): Jwk
    {
        if ($secret === '') {
            throw new JwtException('Symmetric key cannot be empty');
        }
        return Jwk::create(
            kty: 'oct',
            params: ['k' => self::base64UrlEncode($secret)],
            use: 'sig',
            alg: $alg,
            kid: $kid,
        );
    }

    /**
     * JWK (oct) → 对称密钥原始字节
     *
     * @param Jwk $jwk
     * @return string
     * @throws JwtException
     */
    public static function jwkToOct(Jwk $jwk): string
    {
        if ($jwk->getKty() !== 'oct') {
            throw new JwtException('Only oct JWK can be converted to raw secret');
        }
        $k = $jwk->getParam('k');
        if ($k === null) {
            throw new JwtException('oct JWK requires "k" parameter');
        }
        return self::base64UrlDecode($k);
    }

    // ----------------------------------------------------------------------
    // EC 相关内部实现
    // ----------------------------------------------------------------------

    /**
     * 读取 EC 密钥详情
     *
     * @return array<string, mixed>
     * @throws JwtException
     */
    private static function ecDetails(\OpenSSLAsymmetricKey $key): array
    {
        $details = openssl_pkey_get_details($key);
        if ($details === false || ($details['type'] ?? -1) !== OPENSSL_KEYTYPE_EC || !isset($details['ec'])) {
            throw new JwtException('Invalid EC key: not an EC key or details unavailable');
        }

        return $details['ec'];
    }

    /**
     * OpenSSL 曲线名 → JWK crv
     *
     * @throws JwtException 当曲线不受 JOSE 支持时
     */
    private static function curveNameToJwk(string $curveName): string
    {
        $crv = array_search($curveName, self::CURVE_MAP, true);
        if ($crv === false) {
            throw new JwtException("Unsupported EC curve for JOSE: {$curveName}");
        }

        return (string) $crv;
    }

    /**
     * 坐标左补零到曲线固定长度
     *
     * @throws JwtException
     */
    private static function padCoordinate(string $value, int $size): string
    {
        $value = ltrim($value, "\x00");
        if (strlen($value) > $size) {
            throw new JwtException('EC coordinate exceeds curve size');
        }

        return str_pad($value, $size, "\x00", STR_PAD_LEFT);
    }

    /**
     * EC 公钥 JWK → SubjectPublicKeyInfo PEM
     *
     * @throws JwtException
     */
    private static function ecJwkToPem(Jwk $jwk): string
    {
        [$crv, $x, $y] = self::ecJwkCoordinates($jwk);

        $point = "\x04" . $x . $y;
        $algorithm = self::encodeAsn1Sequence(
            "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" . self::CURVE_OID[$crv]
        );
        $spki = self::encodeAsn1Sequence($algorithm . self::encodeAsn1BitString($point));

        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";

        if (openssl_pkey_get_public($pem) === false) {
            throw new JwtException('Failed to construct valid EC PEM from JWK');
        }

        return $pem;
    }

    /**
     * EC 私钥 JWK → SEC1 EC PRIVATE KEY PEM
     *
     * @throws JwtException
     */
    private static function ecJwkToPrivatePem(Jwk $jwk): string
    {
        [$crv, $x, $y] = self::ecJwkCoordinates($jwk);

        $d = $jwk->getParam('d');
        if ($d === null) {
            throw new JwtException('EC private JWK requires "d" parameter');
        }
        $dBin = self::padCoordinate(self::base64UrlDecode((string) $d), self::CURVE_SIZE[$crv]);

        $body = "\x02\x01\x01"
            . self::encodeAsn1OctetString($dBin)
            . self::encodeAsn1Context(0, self::CURVE_OID[$crv])
            . self::encodeAsn1Context(1, self::encodeAsn1BitString("\x04" . $x . $y));

        $der = self::encodeAsn1Sequence($body);

        $pem = "-----BEGIN EC PRIVATE KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END EC PRIVATE KEY-----\n";

        if (openssl_pkey_get_private($pem) === false) {
            throw new JwtException('Failed to construct valid EC private PEM from JWK');
        }

        return $pem;
    }

    /**
     * 提取并校验 EC JWK 的曲线与坐标
     *
     * @return array{0: string, 1: string, 2: string}
     * @throws JwtException
     */
    private static function ecJwkCoordinates(Jwk $jwk): array
    {
        $crv = (string) ($jwk->getParam('crv') ?? '');
        if (!isset(self::CURVE_MAP[$crv])) {
            throw new JwtException("Unsupported EC curve in JWK: {$crv}");
        }

        $x = $jwk->getParam('x');
        $y = $jwk->getParam('y');
        if ($x === null || $y === null) {
            throw new JwtException('EC JWK requires "x" and "y" parameters');
        }

        $size = self::CURVE_SIZE[$crv];

        return [
            $crv,
            self::padCoordinate(self::base64UrlDecode((string) $x), $size),
            self::padCoordinate(self::base64UrlDecode((string) $y), $size),
        ];
    }

    // ----------------------------------------------------------------------
    // 内部辅助方法
    // ----------------------------------------------------------------------

    /**
     * 加载公钥（支持文件路径或 PEM 字符串）
     */
    private static function loadPublicKey(string $pem): \OpenSSLAsymmetricKey
    {
        $content = self::resolvePemContent($pem);
        $key = openssl_pkey_get_public($content);
        if ($key === false) {
            throw new JwtException('Failed to load public key: ' . self::lastSslError());
        }
        return $key;
    }

    /**
     * 加载私钥（支持文件路径或 PEM 字符串）
     */
    private static function loadPrivateKey(string $pem): \OpenSSLAsymmetricKey
    {
        $content = self::resolvePemContent($pem);
        $key = openssl_pkey_get_private($content);
        if ($key === false) {
            throw new JwtException('Failed to load private key: ' . self::lastSslError());
        }
        return $key;
    }

    /**
     * 解析 PEM 内容：文件路径则读取文件，否则视为 PEM 字符串
     */
    private static function resolvePemContent(string $pem): string
    {
        if (is_file($pem)) {
            $content = file_get_contents($pem);
            if ($content === false) {
                throw new JwtException("Failed to read key file: {$pem}");
            }
            return $content;
        }
        return $pem;
    }

    /**
     * base64url 编码（RFC 7515）
     */
    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * base64url 解码
     */
    private static function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        $padLen = $remainder === 0 ? strlen($data) : strlen($data) + (4 - $remainder);
        $padded = str_pad($data, $padLen, '=', STR_PAD_RIGHT);
        $decoded = base64_decode(strtr($padded, '-_', '+/'), true);
        if ($decoded === false) {
            throw new JwtException('Invalid base64url encoding');
        }
        return $decoded;
    }

    /**
     * ASN.1 INTEGER 编码
     */
    private static function encodeAsn1Integer(string $data): string
    {
        // 移除前导零字节（ASN.1 规则）
        $data = ltrim($data, "\x00");
        if ($data === '') {
            $data = "\x00";
        }
        // 若高位为 1，需前补 0x00 防止被识别为负数
        if ((ord($data[0]) & 0x80) !== 0) {
            $data = "\x00" . $data;
        }
        $length = self::encodeAsn1Length(strlen($data));
        return "\x02" . $length . $data;
    }

    /**
     * ASN.1 SEQUENCE 编码
     */
    private static function encodeAsn1Sequence(string $data): string
    {
        return "\x30" . self::encodeAsn1Length(strlen($data)) . $data;
    }

    /**
     * ASN.1 BIT STRING 编码
     */
    private static function encodeAsn1BitString(string $data): string
    {
        // 首字节 0x00 表示未使用位数
        return "\x03" . self::encodeAsn1Length(strlen($data) + 1) . "\x00" . $data;
    }

    /**
     * ASN.1 OCTET STRING 编码
     */
    private static function encodeAsn1OctetString(string $data): string
    {
        return "\x04" . self::encodeAsn1Length(strlen($data)) . $data;
    }

    /**
     * ASN.1 上下文相关标签（constructed）编码
     */
    private static function encodeAsn1Context(int $tag, string $data): string
    {
        return chr(0xA0 | $tag) . self::encodeAsn1Length(strlen($data)) . $data;
    }

    /**
     * ASN.1 长度编码
     */
    private static function encodeAsn1Length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xFF) . $bytes;
            $length >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * 获取最后一个 OpenSSL 错误信息
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
