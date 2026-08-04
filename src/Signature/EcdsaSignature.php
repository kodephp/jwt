<?php

declare(strict_types=1);

namespace Kode\Jwt\Signature;

use Kode\Jwt\Enum\Algorithm;
use Kode\Jwt\Exception\JwtException;

/**
 * ECDSA 签名格式转换器（RFC 7518 §3.4）
 *
 * OpenSSL 产出的 ECDSA 签名是 ASN.1 DER 序列 `SEQUENCE { INTEGER r, INTEGER s }`，
 * 而 JWS 规范要求的是固定长度的 `R || S` 原始拼接（左侧补零到曲线字节长度）。
 * 两者不可直接互换，否则生成的 Token 无法被其他语言的 JOSE 库验签。
 *
 * 本类负责这两种表示之间的无损转换：
 *  - ES256 → 32 + 32 = 64 字节
 *  - ES384 → 48 + 48 = 96 字节
 *  - ES512 → 66 + 66 = 132 字节（P-521 为 521 位，向上取整 66 字节）
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
 */
final class EcdsaSignature
{
    /**
     * DER 编码签名 → JOSE 原始 R||S 拼接
     *
     * @param string $der OpenSSL 输出的 DER 签名
     * @param Algorithm $algorithm ECDSA 算法（决定分量长度）
     * @return string 固定长度的原始签名
     * @throws JwtException 当 DER 结构非法时
     */
    public static function fromDer(string $der, Algorithm $algorithm): string
    {
        $partLength = self::partLength($algorithm);
        [$r, $s] = self::decodeDer($der);

        return self::padComponent($r, $partLength) . self::padComponent($s, $partLength);
    }

    /**
     * JOSE 原始 R||S 拼接 → DER 编码签名
     *
     * @param string $raw 固定长度的原始签名
     * @param Algorithm $algorithm ECDSA 算法
     * @return string DER 签名
     * @throws JwtException 当长度不符合算法要求时
     */
    public static function toDer(string $raw, Algorithm $algorithm): string
    {
        $partLength = self::partLength($algorithm);
        $expected = $partLength * 2;

        if (strlen($raw) !== $expected) {
            throw new JwtException(sprintf(
                'Invalid ECDSA signature length for %s: expected %d bytes, got %d',
                $algorithm->value,
                $expected,
                strlen($raw)
            ));
        }

        $r = substr($raw, 0, $partLength);
        $s = substr($raw, $partLength);

        return self::encodeSequence(self::encodeInteger($r) . self::encodeInteger($s));
    }

    /**
     * 单个分量（R 或 S）的字节长度
     *
     * @throws JwtException 当算法不是 ECDSA 时
     */
    public static function partLength(Algorithm $algorithm): int
    {
        if (!$algorithm->isEcdsa()) {
            throw new JwtException("Not an ECDSA algorithm: {$algorithm->value}");
        }

        return match ($algorithm) {
            Algorithm::ES256 => 32,
            Algorithm::ES384 => 48,
            default => 66,
        };
    }

    /**
     * 解析 DER 序列，返回去除符号位与前导零的 r、s 原始字节
     *
     * @return array{0: string, 1: string}
     * @throws JwtException
     */
    private static function decodeDer(string $der): array
    {
        $offset = 0;
        $length = strlen($der);

        if ($length < 8 || $der[0] !== "\x30") {
            throw new JwtException('Invalid ECDSA DER signature: missing SEQUENCE tag');
        }
        $offset++;

        $seqLength = self::readLength($der, $offset);
        if ($seqLength !== $length - $offset) {
            throw new JwtException('Invalid ECDSA DER signature: sequence length mismatch');
        }

        $r = self::readInteger($der, $offset);
        $s = self::readInteger($der, $offset);

        if ($offset !== $length) {
            throw new JwtException('Invalid ECDSA DER signature: trailing bytes detected');
        }

        return [$r, $s];
    }

    /**
     * 读取 ASN.1 长度字段
     *
     * @throws JwtException
     */
    private static function readLength(string $der, int &$offset): int
    {
        if (!isset($der[$offset])) {
            throw new JwtException('Invalid ECDSA DER signature: unexpected end of data');
        }

        $first = ord($der[$offset++]);
        if ($first < 0x80) {
            return $first;
        }

        $bytes = $first & 0x7F;
        if ($bytes === 0 || $bytes > 4 || strlen($der) < $offset + $bytes) {
            throw new JwtException('Invalid ECDSA DER signature: malformed length');
        }

        $length = 0;
        for ($i = 0; $i < $bytes; $i++) {
            $length = ($length << 8) | ord($der[$offset++]);
        }

        return $length;
    }

    /**
     * 读取 ASN.1 INTEGER，返回去掉符号前导零的原始字节
     *
     * @throws JwtException
     */
    private static function readInteger(string $der, int &$offset): string
    {
        if (($der[$offset] ?? '') !== "\x02") {
            throw new JwtException('Invalid ECDSA DER signature: expected INTEGER tag');
        }
        $offset++;

        $length = self::readLength($der, $offset);
        if ($length <= 0 || strlen($der) < $offset + $length) {
            throw new JwtException('Invalid ECDSA DER signature: malformed INTEGER');
        }

        $value = substr($der, $offset, $length);
        $offset += $length;

        // 去掉 ASN.1 为避免负数而添加的 0x00 前导字节
        return ltrim($value, "\x00");
    }

    /**
     * 左侧补零到固定长度
     *
     * @throws JwtException 当分量长度超出曲线容量时
     */
    private static function padComponent(string $component, int $length): string
    {
        if (strlen($component) > $length) {
            throw new JwtException('Invalid ECDSA signature component: exceeds curve size');
        }

        return str_pad($component, $length, "\x00", STR_PAD_LEFT);
    }

    /**
     * ASN.1 INTEGER 编码（自动处理符号位）
     */
    private static function encodeInteger(string $value): string
    {
        $value = ltrim($value, "\x00");
        if ($value === '') {
            $value = "\x00";
        }
        if ((ord($value[0]) & 0x80) !== 0) {
            $value = "\x00" . $value;
        }

        return "\x02" . self::encodeLength(strlen($value)) . $value;
    }

    /**
     * ASN.1 SEQUENCE 编码
     */
    private static function encodeSequence(string $content): string
    {
        return "\x30" . self::encodeLength(strlen($content)) . $content;
    }

    /**
     * ASN.1 长度编码
     */
    private static function encodeLength(int $length): string
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
}
