<?php

declare(strict_types=1);

namespace Kode\Jwt\Signature;

use Kode\Jwt\Exception\JwtException;
use OpenSSLAsymmetricKey;

/**
 * RSASSA-PSS 签名实现（RFC 8017 §8.1 / §9.1）
 *
 * PHP 的 `openssl_sign()` 只支持 PKCS#1 v1.5 填充，无法直接产出 PS256/PS384/PS512
 * 所需的 PSS 签名。本类在 PHP 层完成 EMSA-PSS 编码/校验，再通过 OpenSSL 的
 * 无填充原始 RSA 运算（`openssl_private_encrypt` / `openssl_public_decrypt`
 * 配合 `OPENSSL_NO_PADDING`）完成模幂运算。
 *
 * 实现细节严格对齐 RFC 8017：
 *  - 盐长度等于摘要长度（sLen = hLen），与 JWA 规范一致
 *  - MGF1 掩码生成函数使用与签名相同的摘要算法
 *  - emBits = modBits - 1，最高位清零
 *
 * 产出的签名可被 OpenSSL（`rsa_padding_mode:pss` + `rsa_pss_saltlen:-1`）
 * 及其他标准 JOSE 库正常验签。
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8017#section-9.1
 */
final class RsaPss
{
    /**
     * 使用 RSASSA-PSS 签名
     *
     * @param string $data 待签名数据
     * @param OpenSSLAsymmetricKey $privateKey RSA 私钥
     * @param string $hash 摘要算法（sha256/sha384/sha512）
     * @return string 原始签名字节
     * @throws JwtException 当密钥不可用或运算失败时
     */
    public static function sign(string $data, OpenSSLAsymmetricKey $privateKey, string $hash): string
    {
        $modBits = self::modulusBits($privateKey);
        $keyLength = intdiv($modBits + 7, 8);

        $em = self::encode($data, $modBits - 1, $hash);
        // 原始 RSA 运算要求输入长度严格等于模数字节数
        $em = str_pad($em, $keyLength, "\x00", STR_PAD_LEFT);

        $signature = '';
        if (!openssl_private_encrypt($em, $signature, $privateKey, OPENSSL_NO_PADDING)) {
            throw new JwtException('Failed to create RSA-PSS signature: ' . self::lastSslError());
        }

        return $signature;
    }

    /**
     * 校验 RSASSA-PSS 签名
     *
     * @param string $data 原始数据
     * @param string $signature 待校验签名
     * @param OpenSSLAsymmetricKey $publicKey RSA 公钥
     * @param string $hash 摘要算法
     * @return bool 校验是否通过
     */
    public static function verify(
        string $data,
        string $signature,
        OpenSSLAsymmetricKey $publicKey,
        string $hash
    ): bool {
        $modBits = self::modulusBits($publicKey);
        $keyLength = intdiv($modBits + 7, 8);

        if (strlen($signature) !== $keyLength) {
            return false;
        }

        $em = '';
        if (!openssl_public_decrypt($signature, $em, $publicKey, OPENSSL_NO_PADDING)) {
            // 清空错误队列，避免污染后续 OpenSSL 调用
            self::lastSslError();
            return false;
        }

        $emBits = $modBits - 1;
        $emLen = intdiv($emBits + 7, 8);

        // 原始运算结果固定为模数长度，需按 emLen 截取（多出的高位必须为 0）
        if (strlen($em) > $emLen) {
            $prefix = substr($em, 0, strlen($em) - $emLen);
            if (trim($prefix, "\x00") !== '') {
                return false;
            }
            $em = substr($em, -$emLen);
        }

        return self::verifyEncoding($data, $em, $emBits, $hash);
    }

    /**
     * EMSA-PSS-ENCODE（RFC 8017 §9.1.1）
     *
     * @throws JwtException 当摘要算法不支持或密钥过短时
     */
    public static function encode(string $message, int $emBits, string $hash): string
    {
        $hLen = self::hashLength($hash);
        $sLen = $hLen;
        $emLen = intdiv($emBits + 7, 8);

        if ($emLen < $hLen + $sLen + 2) {
            throw new JwtException('RSA key is too short for RSA-PSS with the selected hash');
        }

        $mHash = hash($hash, $message, true);
        $salt = random_bytes($sLen);
        $mPrime = str_repeat("\x00", 8) . $mHash . $salt;
        $h = hash($hash, $mPrime, true);

        $ps = str_repeat("\x00", $emLen - $sLen - $hLen - 2);
        $db = $ps . "\x01" . $salt;
        $dbMask = self::mgf1($h, $emLen - $hLen - 1, $hash);
        $maskedDb = $db ^ $dbMask;

        // 清零最高 (8 * emLen - emBits) 位
        $unusedBits = 8 * $emLen - $emBits;
        if ($unusedBits > 0) {
            $maskedDb[0] = chr(ord($maskedDb[0]) & (0xFF >> $unusedBits));
        }

        return $maskedDb . $h . "\xBC";
    }

    /**
     * EMSA-PSS-VERIFY（RFC 8017 §9.1.2）
     */
    public static function verifyEncoding(string $message, string $em, int $emBits, string $hash): bool
    {
        $hLen = self::hashLength($hash);
        $sLen = $hLen;
        $emLen = intdiv($emBits + 7, 8);

        if (strlen($em) !== $emLen || $emLen < $hLen + $sLen + 2) {
            return false;
        }

        if (substr($em, -1) !== "\xBC") {
            return false;
        }

        $maskedDb = substr($em, 0, $emLen - $hLen - 1);
        $h = substr($em, $emLen - $hLen - 1, $hLen);

        $unusedBits = 8 * $emLen - $emBits;
        if ($unusedBits > 0) {
            $mask = (0xFF << (8 - $unusedBits)) & 0xFF;
            if ((ord($maskedDb[0]) & $mask) !== 0) {
                return false;
            }
        }

        $dbMask = self::mgf1($h, $emLen - $hLen - 1, $hash);
        $db = $maskedDb ^ $dbMask;
        if ($unusedBits > 0) {
            $db[0] = chr(ord($db[0]) & (0xFF >> $unusedBits));
        }

        $psLen = $emLen - $sLen - $hLen - 2;
        if (substr($db, 0, $psLen) !== str_repeat("\x00", $psLen)) {
            return false;
        }
        if (($db[$psLen] ?? '') !== "\x01") {
            return false;
        }

        $salt = substr($db, $psLen + 1);
        $mHash = hash($hash, $message, true);
        $mPrime = str_repeat("\x00", 8) . $mHash . $salt;

        return hash_equals(hash($hash, $mPrime, true), $h);
    }

    /**
     * MGF1 掩码生成函数（RFC 8017 附录 B.2.1）
     */
    public static function mgf1(string $seed, int $length, string $hash): string
    {
        if ($length <= 0) {
            return '';
        }

        $output = '';
        for ($counter = 0; strlen($output) < $length; $counter++) {
            $output .= hash($hash, $seed . pack('N', $counter), true);
        }

        return substr($output, 0, $length);
    }

    /**
     * 摘要输出字节数
     *
     * @throws JwtException 当摘要算法不支持时
     */
    private static function hashLength(string $hash): int
    {
        return match ($hash) {
            'sha256' => 32,
            'sha384' => 48,
            'sha512' => 64,
            default => throw new JwtException("Unsupported hash algorithm for RSA-PSS: {$hash}"),
        };
    }

    /**
     * 读取 RSA 模数位数
     *
     * @throws JwtException 当密钥不是 RSA 时
     */
    private static function modulusBits(OpenSSLAsymmetricKey $key): int
    {
        $details = openssl_pkey_get_details($key);
        if ($details === false || ($details['type'] ?? -1) !== OPENSSL_KEYTYPE_RSA) {
            throw new JwtException('RSA-PSS requires an RSA key');
        }

        $bits = (int) ($details['bits'] ?? 0);
        if ($bits < 2048) {
            throw new JwtException('RSA-PSS requires a key of at least 2048 bits');
        }

        return $bits;
    }

    /**
     * 取出并清空 OpenSSL 错误队列
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
