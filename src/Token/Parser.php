<?php

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
     */
    public function parse(string $token, ?string $expectedPlatform = null): Payload
    {
        // 分割Token
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new TokenInvalidException('Invalid token format');
        }

        [$headerEncoded, $payloadEncoded, $signatureEncoded] = $parts;

        // 解码头部
        $header = $this->decodePart($headerEncoded);

        // 解码载荷
        $payloadArray = $this->decodePart($payloadEncoded);

        // 验证签名
        $this->verifySignature("{$headerEncoded}.{$payloadEncoded}", $signatureEncoded, $header['alg'] ?? 'HS256');

        // 验证声明
        $this->validateClaims($payloadArray);

        // 如果指定了期望的平台，验证平台匹配
        if ($expectedPlatform !== null && ($payloadArray['platform'] ?? '') !== $expectedPlatform) {
            throw new TokenInvalidException('Token platform mismatch');
        }

        // 创建Payload对象
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
    }

    /**
     * 解码部分
     *
     * @param string $encoded 编码后的字符串
     * @return array<string, mixed> 解码后的数据
     */
    protected function decodePart(string $encoded): array
    {
        $json = base64_decode(strtr($encoded, '-_', '+/'));
        $data = json_decode($json, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new TokenInvalidException('Invalid JSON in token part');
        }

        return $data;
    }

    /**
     * 验证签名
     */
    protected function verifySignature(string $data, string $signature, string $algorithm): void
    {
        $decodedSignature = base64_decode(strtr($signature, '-_', '+/'));

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
    protected function validateClaims(array $claims): void
    {
        $now = time();

        // 检查是否过期
        if (isset($claims['exp']) && $now > $claims['exp']) {
            throw new TokenExpiredException('Token has expired');
        }

        // 检查是否尚未生效
        if (isset($claims['nbf']) && $now < $claims['nbf']) {
            throw new TokenInvalidException('Token is not yet valid');
        }

        // 检查签发时间
        if (isset($claims['iat']) && $now < $claims['iat']) {
            throw new TokenInvalidException('Token issued in the future');
        }
    }
}
