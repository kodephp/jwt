<?php

namespace Kode\Jwt\Token;

use Kode\Jwt\Contract\Arrayable;
use Kode\Jwt\Contract\Jsonable;
use Kode\Jwt\Exception\JwtException;

class Builder
{
    protected array $claims = [];
    protected array $headers = [
        'typ' => 'JWT',
        'alg' => 'HS256'
    ];
    protected string $secret;
    protected array $config;
    
    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->secret = $config['secret'] ?? '';
        
        // 设置算法
        if (isset($config['algo'])) {
            $this->headers['alg'] = $config['algo'];
        }
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
     */
    public function setUid(int $uid): self
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
     */
    public function setRoles(array $roles): self
    {
        return $this->setClaim('roles', $roles);
    }
    
    /**
     * 设置权限
     */
    public function setPermissions(array $permissions): self
    {
        return $this->setClaim('perms', $permissions);
    }
    
    /**
     * 设置自定义数据
     */
    public function setCustom(array $custom): self
    {
        return $this->setClaim('custom', $custom);
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
        // 验证必要的声明
        if (!isset($this->claims['iat'])) {
            $this->setIssuedAt(time());
        }
        
        if (!isset($this->claims['exp'])) {
            throw new JwtException('Expiration time (exp) is required');
        }
        
        if (!isset($this->claims['jti'])) {
            $this->setId(uniqid('jwt_', true));
        }
        
        // 编码头部
        $header = $this->encodePart($this->headers);
        
        // 编码载荷
        $payload = $this->encodePart($this->claims);
        
        // 创建签名
        $signature = $this->createSignature("{$header}.{$payload}");
        
        return "{$header}.{$payload}.{$signature}";
    }
    
    /**
     * 编码部分
     */
    protected function encodePart(array $data): string
    {
        $json = json_encode($data);
        return rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
    }
    
    /**
     * 创建签名
     */
    protected function createSignature(string $data): string
    {
        $algorithm = $this->headers['alg'] ?? 'HS256';
        
        switch ($algorithm) {
            case 'HS256':
                return $this->signHmac($data, 'sha256');
            case 'HS384':
                return $this->signHmac($data, 'sha384');
            case 'HS512':
                return $this->signHmac($data, 'sha512');
            case 'RS256':
                return $this->signRsa($data, 'sha256');
            case 'RS384':
                return $this->signRsa($data, 'sha384');
            case 'RS512':
                return $this->signRsa($data, 'sha512');
            default:
                throw new JwtException("Unsupported algorithm: {$algorithm}");
        }
    }
    
    /**
     * HMAC签名
     */
    protected function signHmac(string $data, string $algorithm): string
    {
        if (empty($this->secret)) {
            throw new JwtException('Secret is required for HMAC algorithms');
        }
        
        $hash = hash_hmac($algorithm, $data, $this->secret, true);
        return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    }
    
    /**
     * RSA签名
     */
    protected function signRsa(string $data, string $algorithm): string
    {
        $privateKey = $this->config['private_key'] ?? null;
        
        if (empty($privateKey)) {
            throw new JwtException('Private key is required for RSA algorithms');
        }
        
        // 如果是文件路径，读取私钥
        if (is_file($privateKey)) {
            $privateKey = file_get_contents($privateKey);
        }
        
        $key = openssl_pkey_get_private($privateKey);
        
        if (!$key) {
            throw new JwtException('Invalid private key');
        }
        
        $signature = '';
        $result = openssl_sign($data, $signature, $key, $algorithm);
        openssl_free_key($key);
        
        if (!$result) {
            throw new JwtException('Failed to create RSA signature');
        }
        
        return rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
    }
}