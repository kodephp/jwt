<?php

declare(strict_types=1);

namespace Kode\Jwt\Token;

use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Exception\TokenExpiredException;
use Kode\Jwt\Exception\TokenInvalidException;

class Parser
{
    protected string $secret;
    protected string $publicKey;
    /**
     * @var array<string, mixed>
     */
    protected array $config;

    /**
     * 构造函数
     *
     * @param array<string, mixed> $config 配置数组
     */
    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->secret = $config['secret'] ?? '';
        $this->publicKey = $config['public_key'] ?? '';
    }

    /**
     * 解析Token
     *
     * 核心流程包含：结构校验、头部与载荷解码、算法一致性检查、
     * 签名校验、声明校验、平台一致性校验。
     *
     * @param string $token 原始 JWT 字符串
     * @param string|null $expectedPlatform 期望的平台标识，传入后会强制匹配
     * @param bool $ignoreExpiration 是否忽略过期校验，主要用于刷新流程
     * @return Payload
     */
    public function parse(string $token, ?string $expectedPlatform = null, bool $ignoreExpiration = false): Payload
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new TokenInvalidException('Invalid token format', token: $token);
        }

        [$headerEncoded, $payloadEncoded, $signatureEncoded] = $parts;

        $header = $this->decodePart($headerEncoded);
        $payloadArray = $this->decodePart($payloadEncoded);
        $algorithm = (string) ($header['alg'] ?? '');

        if ($algorithm === '') {
            throw new TokenInvalidException('Missing token algorithm', token: $token);
        }

        $this->ensureAllowedAlgorithm($algorithm, $token);

        $this->verifySignature("{$headerEncoded}.{$payloadEncoded}", $signatureEncoded, $algorithm);

        $this->validateClaims($payloadArray, $ignoreExpiration, $token);
        if ($expectedPlatform !== null && ($payloadArray['platform'] ?? '') !== $expectedPlatform) {
            throw new TokenInvalidException(
                'Token platform mismatch',
                token: $token,
                jti: $payloadArray['jti'] ?? null
            );
        }

        try {
            return new Payload(
                uid: $payloadArray['uid'] ?? null,
                username: $payloadArray['username'] ?? null,
                platform: $payloadArray['platform'] ?? '',
                exp: $payloadArray['exp'] ?? 0,
                iat: $payloadArray['iat'] ?? 0,
                jti: $payloadArray['jti'] ?? '',
                roles: $payloadArray['roles'] ?? null,
                perms: $payloadArray['perms'] ?? null,
                custom: $payloadArray['custom'] ?? []
            );
        } catch (\InvalidArgumentException $e) {
            throw new TokenInvalidException(
                'Invalid token payload',
                $e->getMessage(),
                previous: $e,
                token: $token,
                jti: $payloadArray['jti'] ?? null
            );
        }
    }

    /**
     * 解码部分
     *
     * @param string $encoded 编码后的字符串
     * @return array<string, mixed> 解码后的数据
     */
    protected function decodePart(string $encoded): array
    {
        $json = $this->decodeBase64Url($encoded);
        $data = json_decode($json, true);
        if (!is_array($data) || json_last_error() !== JSON_ERROR_NONE) {
            throw new TokenInvalidException('Invalid JSON in token part');
        }

        return $data;
    }

    /**
     * 验证签名
     */
    protected function verifySignature(string $data, string $signature, string $algorithm): void
    {
        $decodedSignature = $this->decodeBase64Url($signature);
        if ($decodedSignature === '') {
            throw new TokenInvalidException('Empty token signature');
        }

        switch ($algorithm) {
            case 'HS256':
                $this->verifyHmac($data, $decodedSignature, 'sha256');
                break;
            case 'HS384':
                $this->verifyHmac($data, $decodedSignature, 'sha384');
                break;
            case 'HS512':
                $this->verifyHmac($data, $decodedSignature, 'sha512');
                break;
            case 'RS256':
                $this->verifyRsa($data, $decodedSignature, 'sha256');
                break;
            case 'RS384':
                $this->verifyRsa($data, $decodedSignature, 'sha384');
                break;
            case 'RS512':
                $this->verifyRsa($data, $decodedSignature, 'sha512');
                break;
            default:
                throw new JwtException("Unsupported algorithm: {$algorithm}");
        }
    }

    /**
     * 验证HMAC签名
     */
    protected function verifyHmac(string $data, string $signature, string $algorithm): void
    {
        if (empty($this->secret)) {
            throw new JwtException('Secret is required for HMAC algorithms');
        }

        $hash = hash_hmac($algorithm, $data, $this->secret, true);

        if (!hash_equals($hash, $signature)) {
            throw new TokenInvalidException('Invalid token signature');
        }
    }

    /**
     * 验证RSA签名
     *
     * @throws JwtException 当公钥无效时抛出异常
     */
    protected function verifyRsa(string $data, string $signature, string $algorithm): void
    {
        if (empty($this->publicKey)) {
            throw new JwtException('Public key is required for RSA algorithms');
        }

        // 如果是文件路径，读取公钥
        if (is_file($this->publicKey)) {
            $publicKeyContent = file_get_contents($this->publicKey);
            if ($publicKeyContent === false) {
                throw new JwtException('Failed to read public key file');
            }
            $publicKey = $publicKeyContent;
        } else {
            $publicKey = $this->publicKey;
        }

        $key = openssl_pkey_get_public($publicKey);

        if (!$key) {
            throw new JwtException('Invalid public key');
        }

        $result = openssl_verify($data, $signature, $key, $algorithm);

        if ($result !== 1) {
            throw new TokenInvalidException('Invalid token signature');
        }
    }

    /**
     * 验证声明
     *
     * @param array<string, mixed> $claims 声明数组
     * @throws TokenExpiredException 当Token已过期时抛出异常
     * @throws TokenInvalidException 当Token尚未生效或签发时间在未来时抛出异常
     */
    protected function validateClaims(array $claims, bool $ignoreExpiration, string $token): void
    {
        $now = time();
        $clockSkew = max(0, (int) ($this->config['clock_skew'] ?? 0));

        $jti = isset($claims['jti']) ? (string) $claims['jti'] : null;
        if ($jti === null || $jti === '') {
            throw new TokenInvalidException('Missing required claim: jti', token: $token);
        }

        $platform = (string) ($claims['platform'] ?? '');
        if ($platform === '') {
            throw new TokenInvalidException('Missing required claim: platform', token: $token, jti: $jti);
        }

        if (!isset($claims['exp'])) {
            throw new TokenInvalidException('Missing required claim: exp', token: $token, jti: $jti);
        }

        if (!$ignoreExpiration && $now > ((int) $claims['exp'] + $clockSkew)) {
            throw new TokenExpiredException('Token has expired', (int) $claims['exp'], token: $token, jti: $jti);
        }

        if (isset($claims['nbf']) && ($now + $clockSkew) < (int) $claims['nbf']) {
            throw new TokenInvalidException('Token is not yet valid', token: $token, jti: $jti);
        }

        if (isset($claims['iat']) && ($now + $clockSkew) < (int) $claims['iat']) {
            throw new TokenInvalidException('Token issued in the future', token: $token, jti: $jti);
        }
    }

    /**
     * 校验算法是否符合配置约束
     *
     * 防止攻击者通过篡改 Header 的 alg 字段绕过预期签名策略。
     *
     * @param string $actualAlgorithm Token 头部声明的算法
     * @param string $token 原始 Token
     * @return void
     */
    protected function ensureAllowedAlgorithm(string $actualAlgorithm, string $token): void
    {
        $expectedAlgorithm = strtoupper((string) ($this->config['algo'] ?? ''));
        $actualAlgorithm = strtoupper($actualAlgorithm);

        if ($actualAlgorithm === 'NONE') {
            throw new TokenInvalidException('The "none" algorithm is forbidden', token: $token);
        }

        if ($expectedAlgorithm !== '' && $actualAlgorithm !== $expectedAlgorithm) {
            throw new TokenInvalidException(
                "Algorithm mismatch: expected {$expectedAlgorithm}, got {$actualAlgorithm}",
                token: $token
            );
        }
    }

    /**
     * Base64URL 安全解码
     *
     * @param string $value 编码字符串
     * @return string 解码结果
     */
    protected function decodeBase64Url(string $value): string
    {
        $padding = 4 - (strlen($value) % 4);
        if ($padding < 4) {
            $value .= str_repeat('=', $padding);
        }

        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        if ($decoded === false) {
            throw new TokenInvalidException('Invalid base64url segment');
        }

        return $decoded;
    }
}
