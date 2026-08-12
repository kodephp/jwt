<?php

declare(strict_types=1);

namespace Kode\Jwt\Token;

use Kode\Jwt\Claim\Confirmation;
use Kode\Jwt\Contract\Arrayable;
use Kode\Jwt\Contract\Jsonable;
use Kode\Jwt\Enum\Algorithm;
use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Signature\Signer;

class Builder
{
    /**
     * @var array<string, mixed>
     */
    protected array $claims = [];

    /**
     * @var array<string, mixed>
     */
    protected array $headers = [
        'typ' => 'JWT',
        'alg' => 'HS256'
    ];

    protected string $secret;

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

        if (isset($config['algo'])) {
            $algorithm = strtoupper((string) $config['algo']);
            if ($algorithm === 'NONE') {
                throw new JwtException('The "none" algorithm is forbidden');
            }
            $this->headers['alg'] = $algorithm;
        }
    }

    /**
     * 重置构建器到初始状态（清空已累积的 claims / headers，恢复默认 typ/alg）
     *
     * 仅用于「有意复用同一个 Builder 实例」的场景。
     * 一般情况下无需调用 —— KodeJwt::builder() 每次都返回全新实例，
     * 不要跨请求共享 Builder，否则会泄漏前次 claims / 碰撞 jti。
     *
     * @return $this
     */
    public function reset(): self
    {
        $this->claims = [];
        $this->headers = [
            'typ' => 'JWT',
            'alg' => 'HS256',
        ];

        return $this;
    }

    /**
     * 设置头部信息
     */
    public function setHeader(string $key, mixed $value): self
    {
        $this->headers[$key] = $value;
        return $this;
    }

    /**
     * 设置声明
     */
    public function setClaim(string $key, mixed $value): self
    {
        $this->claims[$key] = $value;
        return $this;
    }

    /**
     * 批量设置声明
     */
    public function setClaims(array $claims): self
    {
        $this->claims = array_merge($this->claims, $claims);
        return $this;
    }

    /**
     * 设置主题
     */
    public function setSubject(string $subject): self
    {
        return $this->setClaim('sub', $subject);
    }

    /**
     * 设置受众
     */
    public function setAudience(string|array $audience): self
    {
        return $this->setClaim('aud', $audience);
    }

    /**
     * 设置过期时间
     */
    public function setExpiration(int $expiration): self
    {
        return $this->setClaim('exp', $expiration);
    }

    /**
     * 设置生效时间
     */
    public function setNotBefore(int $notBefore): self
    {
        return $this->setClaim('nbf', $notBefore);
    }

    /**
     * 设置签发时间
     */
    public function setIssuedAt(int $issuedAt): self
    {
        return $this->setClaim('iat', $issuedAt);
    }

    /**
     * 设置签发者
     */
    public function setIssuer(string $issuer): self
    {
        return $this->setClaim('iss', $issuer);
    }

    /**
     * 设置JWT ID
     */
    public function setId(string $id): self
    {
        return $this->setClaim('jti', $id);
    }

    /**
     * 从Arrayable对象设置声明
     */
    public function fromArrayable(Arrayable $arrayable): self
    {
        return $this->setClaims($arrayable->toArray());
    }

    /**
     * 从Payload对象设置声明
     */
    public function fromPayload(Payload $payload): self
    {
        return $this->setClaims($payload->toArray());
    }

    /**
     * 设置用户ID
     *
     * @param int|string $uid 用户ID（支持雪花ID等字符串类型）
     * @return $this
     */
    public function setUid(int|string $uid): self
    {
        return $this->setClaim('uid', $uid);
    }

    /**
     * 设置用户名
     */
    public function setUsername(string $username): self
    {
        return $this->setClaim('username', $username);
    }

    /**
     * 设置平台
     */
    public function setPlatform(string $platform): self
    {
        return $this->setClaim('platform', $platform);
    }

    /**
     * 设置角色
     *
     * @param array<string> $roles 角色数组
     * @return $this
     */
    public function setRoles(array $roles): self
    {
        return $this->setClaim('roles', $roles);
    }

    /**
     * 设置权限
     *
     * @param array<string> $permissions 权限数组
     * @return $this
     */
    public function setPermissions(array $permissions): self
    {
        return $this->setClaim('perms', $permissions);
    }

    /**
     * 设置自定义数据
     *
     * @param array<string, mixed> $custom 自定义数据
     * @return $this
     */
    public function setCustom(array $custom): self
    {
        return $this->setClaim('custom', $custom);
    }

    /**
     * 设置一次性 Nonce（防重放）
     *
     * 业务场景：客户端在调用敏感接口时生成一个随机 Nonce 放入请求头，
     * 服务端验证 Nonce 唯一性后放行，避免攻击者重放截获的请求。
     *
     * @param string $nonce 一次性随机值
     * @return $this
     */
    public function setNonce(string $nonce): self
    {
        return $this->setClaim('nonce', $nonce);
    }

    /**
     * 设置 cnf 确认声明（RFC 7800）
     *
     * 将 Token 与某个密钥/证据绑定，典型用途是 DPoP（RFC 9449）：
     * 用 Confirmation::withJwk($publicOrPrivateJwk) 绑定公钥指纹，
     * 资源服务器据此确认请求方持有对应私钥。
     *
     * @param Confirmation $confirmation 确认声明值对象
     * @return $this
     */
    public function setConfirmation(Confirmation $confirmation): self
    {
        return $this->setClaim('cnf', $confirmation->toArray());
    }

    /**
     * 从Jsonable对象设置声明
     */
    public function fromJsonable(Jsonable $jsonable): self
    {
        $data = json_decode($jsonable->toJson(), true);
        if (is_array($data)) {
            return $this->setClaims($data);
        }
        return $this;
    }

    /**
     * 生成Token
     */
    public function build(): string
    {
        if (!isset($this->claims['iat'])) {
            $this->setIssuedAt(time());
        }

        if (!isset($this->claims['exp'])) {
            throw new JwtException('Expiration time (exp) is required');
        }

        if (!isset($this->claims['jti'])) {
            $this->setId(self::generateJti());
        }

        // 自动注入 typ 头部（若未设置）
        if (!isset($this->headers['typ'])) {
            $this->headers['typ'] = 'JWT';
        }

        $header = $this->encodePart($this->headers);
        $payload = $this->encodePart($this->claims);
        $signature = $this->createSignature("{$header}.{$payload}");

        return "{$header}.{$payload}.{$signature}";
    }

    /**
     * 编码部分
     *
     * @param array<string, mixed> $data 要编码的数据
     * @return string 编码后的字符串
     */
    protected function encodePart(array $data): string
    {
        $json = json_encode($data);
        if ($json === false) {
            throw new JwtException('Failed to encode token payload as JSON');
        }
        return rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
    }

    /**
     * 创建签名
     *
     * 全部算法族（HS/RS/ES/PS/EdDSA）统一委托给 Signer 处理，
     * ECDSA 自动完成 DER → R‖S 转换，RSA-PSS 自动使用 EMSA-PSS 填充。
     */
    protected function createSignature(string $data): string
    {
        $algorithm = Signer::resolveAlgorithm((string) ($this->headers['alg'] ?? 'HS256'));
        $signature = Signer::sign($data, $algorithm, $this->resolveSigningKey($algorithm));

        return rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
    }

    /**
     * 解析当前算法所需的签名密钥
     *
     * - HMAC：使用配置中的 secret
     * - RSA / ECDSA / RSA-PSS / EdDSA：使用配置中的 private_key（支持 PEM 或文件路径）
     *
     * @throws JwtException 当密钥缺失时
     */
    protected function resolveSigningKey(Algorithm $algorithm): string
    {
        if ($algorithm->isHmac()) {
            if ($this->secret === '') {
                throw new JwtException('Secret is required for HMAC algorithms');
            }
            return $this->secret;
        }

        $privateKey = (string) ($this->config['private_key'] ?? '');
        if ($privateKey === '') {
            throw new JwtException(
                "Private key is required for {$algorithm->family()} algorithms ({$algorithm->value})"
            );
        }

        return $privateKey;
    }

    /**
     * 生成高熵 JTI
     *
     * 使用密码学安全随机数（random_bytes）生成 32 字节（256 bit）随机值，
     * 远高于 UUID v4 的 122 bit 熵，足以满足防碰撞与防预测需求。
     *
     * @return string
     */
    protected static function generateJti(): string
    {
        return 'jwt_' . bin2hex(random_bytes(16));
    }

    /**
     * 构建多签名的 JWS 格式
     *
     * @param array<array{key: string, keyId?: string}> $signers 签名者配置
     * @return string JWS JSON 序列化字符串
     */
    public function buildMultiSignature(array $signers): string
    {
        if (!isset($this->claims['iat'])) {
            $this->setIssuedAt(time());
        }

        if (!isset($this->claims['exp'])) {
            throw new JwtException('Expiration time (exp) is required');
        }

        if (!isset($this->claims['jti'])) {
            $this->setId(self::generateJti());
        }

        $header = $this->encodePart($this->headers);
        $payload = $this->encodePart($this->claims);
        $signatures = [];

        foreach ($signers as $index => $signer) {
            $key = $signer['key'] ?? '';
            $keyId = $signer['keyId'] ?? "signer_{$index}";
            $algorithm = $this->headers['alg'] ?? 'HS256';

            $signature = $this->signWithKey("{$header}.{$payload}", $key, $algorithm);
            $sigHeader = ['alg' => $algorithm, 'kid' => $keyId];
            $encodedSigHeader = $this->encodePart($sigHeader);

            $signatures[] = [
                'protected' => $encodedSigHeader,
                'signature' => $signature
            ];
        }

        return json_encode([
            'payload' => $payload,
            'signatures' => $signatures
        ], JSON_UNESCAPED_SLASHES);
    }

    /**
     * 使用指定密钥创建签名（多签名 / 分离式签名场景）
     *
     * 支持全部算法族，密钥语义与 Signer 一致：
     * HMAC 传入共享密钥，其余算法传入 PEM 私钥或私钥文件路径。
     */
    private function signWithKey(string $data, string $key, string $algorithm): string
    {
        $resolved = Algorithm::tryFromName($algorithm);
        if ($resolved === null) {
            throw new JwtException("Unsupported algorithm for multi-signature: {$algorithm}");
        }

        $signature = Signer::sign($data, $resolved, $key);

        return rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
    }

    /**
     * 创建 detached 签名（仅签名部分，用于分离式签名）
     *
     * @param array<array{key: string, keyId?: string}> $signers 签名者配置
     * @return string 签名的 base64url 编码
     */
    public function buildDetachedSignature(array $signers): string
    {
        if (!isset($this->claims['iat'])) {
            $this->setIssuedAt(time());
        }

        if (!isset($this->claims['exp'])) {
            throw new JwtException('Expiration time (exp) is required');
        }

        if (!isset($this->claims['jti'])) {
            $this->setId(self::generateJti());
        }

        $header = $this->encodePart($this->headers);
        $payload = $this->encodePart($this->claims);
        $signatures = [];

        foreach ($signers as $index => $signer) {
            $key = $signer['key'] ?? '';
            $keyId = $signer['keyId'] ?? "signer_{$index}";
            $algorithm = $this->headers['alg'] ?? 'HS256';

            $signature = $this->signWithKey("{$header}.{$payload}", $key, $algorithm);
            $sigHeader = ['alg' => $algorithm, 'kid' => $keyId];
            $encodedSigHeader = $this->encodePart($sigHeader);

            $signatures[] = [
                'protected' => $encodedSigHeader,
                'signature' => $signature
            ];
        }

        return json_encode($signatures, JSON_UNESCAPED_SLASHES);
    }
}
