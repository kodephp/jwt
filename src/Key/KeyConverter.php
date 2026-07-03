<?php

declare(strict_types=1);

namespace Kode\Jwt\Key;

use Kode\Jwt\Exception\JwtException;

/**
 * 密钥格式转换器
 *
 * 在 PEM 格式（OpenSSL 原生）与 JWK 格式（RFC 7517）之间互转，
 * 让现有 PEM 密钥基础设施能无缝接入 JWK 工作流。
 *
 * 支持的转换：
 *  - RSA 公钥 PEM → JWK（提取 n/e 参数）
 *  - RSA 私钥 PEM → JWK（提取完整参数）
 *  - JWK（RSA 公钥）→ PEM
 *  - 对称密钥 ↔ JWK（oct）
 *
 * 安全说明：
 *  - EC 密钥的 PEM ↔ JWK 转换由于坐标编码复杂度，建议使用 openssl_pkey_get_private
 *    配合 JWK 直接验签，本类暂不实现 EC 参数级转换
 *  - 所有 base64 编解码均使用 URL-safe 字符集（RFC 7515）
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-6.3 RFC 7518 RSA JWK 参数
 */
final class KeyConverter
{
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
     * JWK → PEM
     *
     * 仅支持 RSA 公钥（n/e 参数）转换为 PEM 格式。
     * 私钥 JWK 转换为 PEM 需要完整私钥参数，出于安全考虑建议直接使用 JWK 验签。
     *
     * @param Jwk $jwk
     * @return string PEM 格式公钥
     * @throws JwtException 当 JWK 类型不支持或参数缺失时
     */
    public static function jwkToPem(Jwk $jwk): string
    {
        if ($jwk->getKty() !== 'RSA') {
            throw new JwtException('Only RSA JWK can be converted to PEM');
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
