<?php

declare(strict_types=1);

namespace Kode\Jwt\Signature;

use Kode\Jwt\Enum\Algorithm;
use Kode\Jwt\Exception\JwtException;
use OpenSSLAsymmetricKey;

/**
 * 统一 JWS 签名 / 验签服务
 *
 * 将五大算法族的差异收敛到一个入口，供 Builder、Parser、MultiSignature、
 * DPoP 等所有需要签名能力的模块复用，避免各处重复实现导致行为不一致：
 *
 *  | 算法族   | 实现方式                                        |
 *  |----------|-------------------------------------------------|
 *  | HS*      | hash_hmac + hash_equals 定时安全比较            |
 *  | RS*      | openssl_sign / openssl_verify（PKCS#1 v1.5）    |
 *  | PS*      | RsaPss（EMSA-PSS + 原始 RSA 运算）              |
 *  | ES*      | openssl_sign + DER↔R‖S 转换（RFC 7518 §3.4）    |
 *  | EdDSA    | libsodium Ed25519 detached 签名                 |
 *
 * 密钥资源（OpenSSLAsymmetricKey）按内容哈希缓存，避免高频签发时重复解析 PEM。
 */
final class Signer
{
    /**
     * 已解析的私钥资源缓存
     *
     * @var array<string, OpenSSLAsymmetricKey>
     */
    private static array $privateKeyCache = [];

    /**
     * 已解析的公钥资源缓存
     *
     * @var array<string, OpenSSLAsymmetricKey>
     */
    private static array $publicKeyCache = [];

    /**
     * 密钥文件内容缓存（按路径 + mtime）
     *
     * @var array<string, array{mtime: int, content: string}>
     */
    private static array $fileCache = [];

    /**
     * 生成签名（返回 JOSE 规范的原始签名字节）
     *
     * @param string $data 待签名的 `header.payload` 字符串
     * @param Algorithm $algorithm 签名算法
     * @param string $key HMAC 密钥 / PEM 私钥 / 私钥文件路径
     * @return string 原始签名字节
     * @throws JwtException 当密钥缺失、算法不支持或签名失败时
     */
    public static function sign(string $data, Algorithm $algorithm, string $key): string
    {
        self::ensureSupported($algorithm);

        if ($key === '') {
            throw new JwtException("Signing key is required for {$algorithm->value}");
        }

        if ($algorithm->isHmac()) {
            return hash_hmac((string) $algorithm->hashAlgorithm(), $data, $key, true);
        }

        if ($algorithm->isEddsa()) {
            return Ed25519::sign($data, $key);
        }

        $privateKey = self::loadPrivateKey($key);

        if ($algorithm->isRsapss()) {
            return RsaPss::sign($data, $privateKey, (string) $algorithm->hashAlgorithm());
        }

        $signature = '';
        if (!openssl_sign($data, $signature, $privateKey, (int) $algorithm->opensslAlgorithm())) {
            throw new JwtException(
                "Failed to create {$algorithm->value} signature: " . self::lastSslError()
            );
        }

        if ($algorithm->isEcdsa()) {
            // OpenSSL 输出 DER，JWS 要求固定长度 R||S
            return EcdsaSignature::fromDer($signature, $algorithm);
        }

        return $signature;
    }

    /**
     * 校验签名
     *
     * @param string $data 原始 `header.payload` 字符串
     * @param string $signature 原始签名字节（已 base64url 解码）
     * @param Algorithm $algorithm 签名算法
     * @param string $key HMAC 密钥 / PEM 公钥 / 公钥文件路径
     * @return bool 校验是否通过
     * @throws JwtException 当密钥缺失或算法不支持时
     */
    public static function verify(string $data, string $signature, Algorithm $algorithm, string $key): bool
    {
        self::ensureSupported($algorithm);

        if ($key === '') {
            throw new JwtException("Verification key is required for {$algorithm->value}");
        }

        if ($signature === '') {
            return false;
        }

        if ($algorithm->isHmac()) {
            $expected = hash_hmac((string) $algorithm->hashAlgorithm(), $data, $key, true);
            return hash_equals($expected, $signature);
        }

        if ($algorithm->isEddsa()) {
            return Ed25519::verify($data, $signature, $key);
        }

        $publicKey = self::loadPublicKey($key);

        if ($algorithm->isRsapss()) {
            return RsaPss::verify($data, $signature, $publicKey, (string) $algorithm->hashAlgorithm());
        }

        if ($algorithm->isEcdsa()) {
            $expectedLength = (int) $algorithm->signatureLength();
            if (strlen($signature) !== $expectedLength) {
                return false;
            }
            try {
                $signature = EcdsaSignature::toDer($signature, $algorithm);
            } catch (JwtException) {
                return false;
            }
        }

        $result = openssl_verify($data, $signature, $publicKey, (int) $algorithm->opensslAlgorithm());
        if ($result === -1) {
            self::lastSslError();
            return false;
        }

        return $result === 1;
    }

    /**
     * 解析算法字符串，未知算法抛出异常
     *
     * @throws JwtException
     */
    public static function resolveAlgorithm(string $algorithm): Algorithm
    {
        $resolved = Algorithm::tryFromName($algorithm);
        if ($resolved === null) {
            throw new JwtException("Unsupported algorithm: {$algorithm}");
        }

        return $resolved;
    }

    /**
     * 清空密钥缓存（配置重载 / 密钥轮换后调用）
     */
    public static function flushKeyCache(): void
    {
        self::$privateKeyCache = [];
        self::$publicKeyCache = [];
        self::$fileCache = [];
    }

    /**
     * 校验运行环境是否具备该算法所需扩展
     *
     * @throws JwtException
     */
    private static function ensureSupported(Algorithm $algorithm): void
    {
        if (!$algorithm->isSupported()) {
            throw new JwtException(sprintf(
                'Algorithm %s requires the %s extension',
                $algorithm->value,
                (string) $algorithm->requiredExtension()
            ));
        }
    }

    /**
     * 加载并缓存私钥资源
     *
     * @throws JwtException
     */
    private static function loadPrivateKey(string $key): OpenSSLAsymmetricKey
    {
        $content = self::readKeyMaterial($key);
        $cacheKey = hash('sha256', $content);

        if (isset(self::$privateKeyCache[$cacheKey])) {
            return self::$privateKeyCache[$cacheKey];
        }

        $resource = openssl_pkey_get_private($content);
        if ($resource === false) {
            throw new JwtException('Invalid private key: ' . self::lastSslError());
        }

        return self::$privateKeyCache[$cacheKey] = $resource;
    }

    /**
     * 加载并缓存公钥资源
     *
     * 支持直接传入私钥 PEM（自动提取公钥），便于本地自签自验场景。
     *
     * @throws JwtException
     */
    private static function loadPublicKey(string $key): OpenSSLAsymmetricKey
    {
        $content = self::readKeyMaterial($key);
        $cacheKey = hash('sha256', $content);

        if (isset(self::$publicKeyCache[$cacheKey])) {
            return self::$publicKeyCache[$cacheKey];
        }

        $resource = openssl_pkey_get_public($content);

        if ($resource === false) {
            // 兼容传入私钥的场景：从私钥中导出公钥
            $private = openssl_pkey_get_private($content);
            if ($private !== false) {
                $details = openssl_pkey_get_details($private);
                if ($details !== false && isset($details['key'])) {
                    $resource = openssl_pkey_get_public((string) $details['key']);
                }
            }
        }

        if ($resource === false) {
            throw new JwtException('Invalid public key: ' . self::lastSslError());
        }

        return self::$publicKeyCache[$cacheKey] = $resource;
    }

    /**
     * 读取密钥内容（支持文件路径，按 mtime 缓存）
     *
     * @throws JwtException
     */
    private static function readKeyMaterial(string $key): string
    {
        if (str_contains($key, '-----BEGIN') || strlen($key) > 4096) {
            return $key;
        }

        if (!is_file($key)) {
            return $key;
        }

        clearstatcache(true, $key);
        $mtime = @filemtime($key);
        if ($mtime === false) {
            throw new JwtException("Failed to stat key file: {$key}");
        }

        if (isset(self::$fileCache[$key]) && self::$fileCache[$key]['mtime'] === $mtime) {
            return self::$fileCache[$key]['content'];
        }

        $content = file_get_contents($key);
        if ($content === false) {
            throw new JwtException("Failed to read key file: {$key}");
        }

        self::$fileCache[$key] = ['mtime' => $mtime, 'content' => $content];

        return $content;
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
