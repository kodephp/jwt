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
     * RSA 公钥资源缓存
     *
     * 键为公钥内容的 md5 hash，值为 openssl_pkey_get_public 解析后的资源。
     * 避免每次验签都重复读取公钥文件并解析。
     *
     * @var array<string, \OpenSSLAsymmetricKey|resource>
     */
    protected array $publicKeyCache = [];

    /**
     * 公钥文件内容缓存（按文件路径 + mtime 缓存）
     *
     * 避免每次验签都执行 file_get_contents。当文件 mtime 变化时自动失效。
     *
     * @var array<string, array{mtime: int, content: string}>
     */
    protected array $publicKeyFileCache = [];

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
     * @param array<string, mixed> $expectedClaims 期望的声明约束（如 iss / aud / sub）
     * @return Payload
     */
    public function parse(
        string $token,
        ?string $expectedPlatform = null,
        bool $ignoreExpiration = false,
        array $expectedClaims = []
    ): Payload {
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

        $this->validateExpectedClaims($payloadArray, $expectedClaims, $token);

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
                custom: $payloadArray['custom'] ?? [],
                nonce: isset($payloadArray['nonce']) ? (string) $payloadArray['nonce'] : null,
                audience: $payloadArray['aud'] ?? $payloadArray['audience'] ?? null,
                issuer: $payloadArray['iss'] ?? $payloadArray['issuer'] ?? null,
                subject: $payloadArray['sub'] ?? $payloadArray['subject'] ?? null
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
     * 公钥资源会被缓存（以公钥内容的 md5 hash 为键），避免每次验签
     * 都重复读取公钥文件并调用 openssl_pkey_get_public 解析。
     * 公钥文件内容也按"路径 + mtime"缓存，避免每次验签都执行 file_get_contents。
     *
     * @throws JwtException 当公钥无效时抛出异常
     */
    protected function verifyRsa(string $data, string $signature, string $algorithm): void
    {
        if (empty($this->publicKey)) {
            throw new JwtException('Public key is required for RSA algorithms');
        }

        // 如果是文件路径，按"路径 + mtime"缓存读取公钥内容，避免每次验签都执行文件 IO
        if (is_file($this->publicKey)) {
            $publicKey = $this->readPublicKeyFile($this->publicKey);
        } else {
            $publicKey = $this->publicKey;
        }

        // 以公钥内容的 md5 hash 作为缓存键
        $cacheKey = md5($publicKey);

        // 命中缓存则直接复用已解析的公钥资源
        if (isset($this->publicKeyCache[$cacheKey])) {
            $key = $this->publicKeyCache[$cacheKey];
        } else {
            $key = openssl_pkey_get_public($publicKey);

            if (!$key) {
                throw new JwtException('Invalid public key');
            }

            // 缓存解析后的公钥资源
            $this->publicKeyCache[$cacheKey] = $key;
        }

        $result = openssl_verify($data, $signature, $key, $algorithm);

        if ($result !== 1) {
            throw new TokenInvalidException('Invalid token signature');
        }
    }

    /**
     * 按"路径 + mtime"缓存读取公钥文件内容
     *
     * 文件被修改（mtime 变化）时自动失效，重新读取。
     */
    protected function readPublicKeyFile(string $path): string
    {
        clearstatcache(true, $path);
        $mtime = @filemtime($path);
        if ($mtime === false) {
            throw new JwtException('Failed to stat public key file');
        }

        if (isset($this->publicKeyFileCache[$path]) && $this->publicKeyFileCache[$path]['mtime'] === $mtime) {
            return $this->publicKeyFileCache[$path]['content'];
        }

        $content = file_get_contents($path);
        if ($content === false) {
            throw new JwtException('Failed to read public key file');
        }

        $this->publicKeyFileCache[$path] = ['mtime' => $mtime, 'content' => $content];
        return $content;
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
     * 算法白名单强制校验
     *
     * 安全防线（按优先级）：
     *  1. 永久禁用 "none" 算法，防止未签名 Token 攻击
     *  2. 若配置 allowed_algorithms 数组，则 Token alg 必须命中白名单（适用于密钥轮换多算法并存场景）
     *  3. 若配置 algo 单值，则 Token alg 必须严格匹配，防止算法混淆攻击
     *     （例如：服务端用 RS256 公钥，攻击者伪造 HS256 Token 用公钥当密钥签名）
     *
     * @param string $actualAlgorithm Token header 中的 alg 值
     * @param string $token 原始 Token 字符串（用于异常上下文）
     * @throws TokenInvalidException 当算法被禁用或不匹配时抛出
     */
    protected function ensureAllowedAlgorithm(string $actualAlgorithm, string $token): void
    {
        $actualUpper = strtoupper($actualAlgorithm);

        // 1. 永久禁用 none 算法
        if ($actualUpper === 'NONE') {
            throw new TokenInvalidException('The "none" algorithm is forbidden', token: $token);
        }

        // 2. 显式白名单优先（适用于密钥轮换、多算法并存场景）
        $allowedAlgorithms = $this->config['allowed_algorithms'] ?? null;
        if (is_array($allowedAlgorithms) && !empty($allowedAlgorithms)) {
            $allowedUpper = array_map('strtoupper', array_map('strval', $allowedAlgorithms));
            if (!in_array($actualUpper, $allowedUpper, true)) {
                throw new TokenInvalidException(
                    "Algorithm not allowed: {$actualAlgorithm}. Allowed: " . implode(', ', $allowedUpper),
                    token: $token
                );
            }
            return;
        }

        // 3. 单算法严格匹配，防止算法混淆攻击
        $expectedAlgorithm = strtoupper((string) ($this->config['algo'] ?? ''));
        if ($expectedAlgorithm !== '' && $actualUpper !== $expectedAlgorithm) {
            throw new TokenInvalidException(
                "Algorithm mismatch: expected {$expectedAlgorithm}, got {$actualUpper}",
                token: $token
            );
        }
    }

    /**
     * 校验业务期望的标准声明（iss/aud/sub/自定义）
     *
     * 用于加强 Token 的业务约束：
     *  - iss：签发者必须与预期一致，防止跨服务/跨租户混用
     *  - aud：受众必须命中预期列表
     *  - sub：主体标识必须匹配
     *  - 其他：键值精确匹配
     *
     * @param array<string, mixed> $payload 解码后的 Payload
     * @param array<string, mixed> $expected 期望的声明约束
     * @param string $token 原始 Token（用于异常信息）
     * @return void
     */
    protected function validateExpectedClaims(array $payload, array $expected, string $token): void
    {
        if (empty($expected)) {
            return;
        }

        $jti = isset($payload['jti']) ? (string) $payload['jti'] : null;

        // 校验签发者（iss）
        if (isset($expected['iss']) || isset($expected['issuer'])) {
            $expectedIssuer = (string) ($expected['iss'] ?? $expected['issuer']);
            $actualIssuer = (string) ($payload['iss'] ?? '');
            if ($expectedIssuer !== '' && $actualIssuer !== $expectedIssuer) {
                throw new TokenInvalidException(
                    "Issuer mismatch: expected {$expectedIssuer}, got '{$actualIssuer}'",
                    token: $token,
                    jti: $jti
                );
            }
        }

        // 校验受众（aud）
        if (isset($expected['aud']) || isset($expected['audience'])) {
            $expectedAud = $expected['aud'] ?? $expected['audience'];
            $actualAud = $payload['aud'] ?? $payload['audience'] ?? null;
            $expectedList = is_array($expectedAud) ? $expectedAud : [$expectedAud];
            $actualList = is_array($actualAud) ? $actualAud : [$actualAud];

            $intersect = array_intersect((array) $expectedList, (array) $actualList);
            if (empty($intersect)) {
                throw new TokenInvalidException(
                    'Audience mismatch: expected one of ' . implode(',', array_map('strval', $expectedList))
                    . ', got ' . implode(',', array_map('strval', $actualList)),
                    token: $token,
                    jti: $jti
                );
            }
        }

        // 校验主体（sub）
        if (isset($expected['sub']) || isset($expected['subject'])) {
            $expectedSub = (string) ($expected['sub'] ?? $expected['subject']);
            $actualSub = (string) ($payload['sub'] ?? '');
            if ($expectedSub !== '' && $actualSub !== $expectedSub) {
                throw new TokenInvalidException(
                    "Subject mismatch: expected {$expectedSub}, got '{$actualSub}'",
                    token: $token,
                    jti: $jti
                );
            }
        }

        // 其他声明：精确匹配
        foreach ($expected as $key => $value) {
            if (in_array($key, ['iss', 'issuer', 'aud', 'audience', 'sub', 'subject'], true)) {
                continue;
            }
            if (($payload[$key] ?? null) !== $value) {
                throw new TokenInvalidException(
                    "Claim mismatch: expected {$key}=" . json_encode($value)
                    . ', got ' . json_encode($payload[$key] ?? null),
                    token: $token,
                    jti: $jti
                );
            }
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
