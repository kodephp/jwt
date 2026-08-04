<?php

declare(strict_types=1);

namespace Kode\Jwt\Signature;

use Kode\Jwt\Exception\JwtException;

/**
 * Ed25519（EdDSA）签名支持（RFC 8032 / RFC 8037）
 *
 * PHP 的 openssl 扩展未暴露 Ed25519 的签名接口，因此这里使用 libsodium
 * （`ext-sodium`，PHP 7.2 起随发行版内置）完成签名与验签，同时提供
 * PKCS#8 / SPKI PEM 与原始 32 字节密钥之间的互转，保证与 OpenSSL、
 * 其他 JOSE 实现生成的密钥完全互通。
 *
 * DER 结构（固定长度，无需完整 ASN.1 解析器）：
 *  - 私钥 PKCS#8：`302e020100300506032b657004220420` + 32 字节种子（共 48 字节）
 *  - 公钥 SPKI：  `302a300506032b6570032100` + 32 字节公钥（共 44 字节）
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8037 RFC 8037 - CFRG Algorithms for JOSE
 */
final class Ed25519
{
    /**
     * PKCS#8 Ed25519 私钥 DER 前缀
     */
    private const string PRIVATE_DER_PREFIX = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20";

    /**
     * SPKI Ed25519 公钥 DER 前缀
     */
    private const string PUBLIC_DER_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

    /**
     * 生成 Ed25519 密钥对
     *
     * @return array{private: string, public: string, seed: string, publicRaw: string}
     *         private/public 为 PEM 字符串，seed/publicRaw 为原始 32 字节
     * @throws JwtException 当 sodium 扩展缺失时
     */
    public static function generateKeyPair(): array
    {
        self::ensureSodium();

        $keyPair = sodium_crypto_sign_keypair();
        $secretKey = sodium_crypto_sign_secretkey($keyPair);
        $publicRaw = sodium_crypto_sign_publickey($keyPair);
        // libsodium 的 secretkey 为 seed(32) || publicKey(32)
        $seed = substr($secretKey, 0, 32);

        return [
            'private' => self::seedToPem($seed),
            'public' => self::publicKeyToPem($publicRaw),
            'seed' => $seed,
            'publicRaw' => $publicRaw,
        ];
    }

    /**
     * 使用 Ed25519 私钥签名
     *
     * @param string $data 待签名数据
     * @param string $key PEM 私钥、文件路径，或 32 字节种子 / 64 字节 sodium 私钥
     * @return string 64 字节签名
     * @throws JwtException
     */
    public static function sign(string $data, string $key): string
    {
        self::ensureSodium();

        $secretKey = self::resolveSecretKey($key);

        return sodium_crypto_sign_detached($data, $secretKey);
    }

    /**
     * 校验 Ed25519 签名
     *
     * @param string $data 原始数据
     * @param string $signature 64 字节签名
     * @param string $key PEM 公钥、文件路径，或 32 字节原始公钥
     * @return bool
     * @throws JwtException
     */
    public static function verify(string $data, string $signature, string $key): bool
    {
        self::ensureSodium();

        if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }

        $publicKey = self::resolvePublicKey($key);

        return sodium_crypto_sign_verify_detached($signature, $data, $publicKey);
    }

    /**
     * 32 字节种子 → PKCS#8 PEM 私钥
     *
     * @throws JwtException 当长度非法时
     */
    public static function seedToPem(string $seed): string
    {
        if (strlen($seed) !== 32) {
            throw new JwtException('Ed25519 seed must be exactly 32 bytes');
        }

        $der = self::PRIVATE_DER_PREFIX . $seed;

        return "-----BEGIN PRIVATE KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PRIVATE KEY-----\n";
    }

    /**
     * 32 字节公钥 → SPKI PEM 公钥
     *
     * @throws JwtException 当长度非法时
     */
    public static function publicKeyToPem(string $publicKey): string
    {
        if (strlen($publicKey) !== 32) {
            throw new JwtException('Ed25519 public key must be exactly 32 bytes');
        }

        $der = self::PUBLIC_DER_PREFIX . $publicKey;

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /**
     * PEM 私钥 → 32 字节种子
     *
     * @throws JwtException 当 PEM 非 Ed25519 私钥时
     */
    public static function pemToSeed(string $pem): string
    {
        $der = self::pemToDer($pem, 'PRIVATE KEY');

        if (!str_starts_with($der, self::PRIVATE_DER_PREFIX) || strlen($der) !== 48) {
            throw new JwtException('Not a valid Ed25519 PKCS#8 private key');
        }

        return substr($der, strlen(self::PRIVATE_DER_PREFIX));
    }

    /**
     * PEM 公钥 → 32 字节公钥
     *
     * @throws JwtException 当 PEM 非 Ed25519 公钥时
     */
    public static function pemToPublicKey(string $pem): string
    {
        $der = self::pemToDer($pem, 'PUBLIC KEY');

        if (!str_starts_with($der, self::PUBLIC_DER_PREFIX) || strlen($der) !== 44) {
            throw new JwtException('Not a valid Ed25519 SPKI public key');
        }

        return substr($der, strlen(self::PUBLIC_DER_PREFIX));
    }

    /**
     * 由种子推导公钥
     *
     * @throws JwtException
     */
    public static function publicKeyFromSeed(string $seed): string
    {
        self::ensureSodium();

        if (strlen($seed) !== 32) {
            throw new JwtException('Ed25519 seed must be exactly 32 bytes');
        }

        return sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
    }

    /**
     * 解析出 libsodium 需要的 64 字节私钥
     *
     * @throws JwtException
     */
    private static function resolveSecretKey(string $key): string
    {
        $material = self::readMaterial($key);

        if (strlen($material) === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES && !self::looksLikePem($material)) {
            return $material;
        }

        $seed = self::looksLikePem($material)
            ? self::pemToSeed($material)
            : $material;

        if (strlen($seed) !== 32) {
            throw new JwtException('Invalid Ed25519 private key material');
        }

        return sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
    }

    /**
     * 解析出 32 字节公钥
     *
     * @throws JwtException
     */
    private static function resolvePublicKey(string $key): string
    {
        $material = self::readMaterial($key);

        if (self::looksLikePem($material)) {
            return self::pemToPublicKey($material);
        }

        if (strlen($material) !== 32) {
            throw new JwtException('Invalid Ed25519 public key material');
        }

        return $material;
    }

    /**
     * 支持传入文件路径
     */
    private static function readMaterial(string $key): string
    {
        if ($key === '') {
            throw new JwtException('Ed25519 key is required');
        }

        // 仅当字符串较短且确实是文件时才做 IO，避免把 PEM 内容当路径
        if (strlen($key) < 4096 && !str_contains($key, "\n") && is_file($key)) {
            $content = file_get_contents($key);
            if ($content === false) {
                throw new JwtException("Failed to read Ed25519 key file: {$key}");
            }
            return $content;
        }

        return $key;
    }

    private static function looksLikePem(string $material): bool
    {
        return str_contains($material, '-----BEGIN');
    }

    /**
     * PEM → DER
     *
     * @throws JwtException
     */
    private static function pemToDer(string $pem, string $label): string
    {
        $pem = self::readMaterial($pem);

        $pattern = '/-----BEGIN ' . preg_quote($label, '/') . '-----(.*?)-----END '
            . preg_quote($label, '/') . '-----/s';

        if (preg_match($pattern, $pem, $matches) !== 1) {
            throw new JwtException("Invalid PEM: missing {$label} block");
        }

        $der = base64_decode(preg_replace('/\s+/', '', $matches[1]) ?? '', true);
        if ($der === false) {
            throw new JwtException('Invalid PEM: base64 decode failed');
        }

        return $der;
    }

    /**
     * @throws JwtException 当 sodium 扩展不可用时
     */
    private static function ensureSodium(): void
    {
        if (!extension_loaded('sodium')) {
            throw new JwtException('EdDSA (Ed25519) requires the sodium extension');
        }
    }
}
