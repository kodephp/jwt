<?php

namespace Kode\Jwt\Token;

use Kode\Jwt\Contract\Arrayable;

final readonly class Payload implements Arrayable
{
    public function __construct(
        public int $uid,
        public string $username,
        public string $platform,
        public int $exp,
        public int $iat,
        public string $jti,
        public ?array $roles = null,
        public ?array $perms = null,
        public array $custom = []
    ) {}

    public function toArray(): array
    {
        return get_object_vars($this);
    }

    /**
     * 从数组创建Payload实例
     * 
     * @param array $data 包含Payload数据的数组
     * @return static
     * @throws \InvalidArgumentException 当必需字段缺失时抛出异常
     */
    public static function fromArray(array $data): static
    {
        // 验证必需字段
        $requiredFields = ['uid', 'username', 'platform', 'exp', 'iat', 'jti'];
        foreach ($requiredFields as $field) {
            if (!isset($data[$field])) {
                throw new \InvalidArgumentException("Missing required field: {$field}");
            }
        }

        return new static(
            (int) $data['uid'],
            (string) $data['username'],
            (string) $data['platform'],
            (int) $data['exp'],
            (int) $data['iat'],
            (string) $data['jti'],
            isset($data['roles']) ? (array) $data['roles'] : null,
            isset($data['perms']) ? (array) $data['perms'] : null,
            isset($data['custom']) ? (array) $data['custom'] : []
        );
    }

    /**
     * 创建一个包含自定义数据的Payload实例
     * 
     * @param int $uid 用户ID
     * @param string $username 用户名
     * @param string $platform 平台标识
     * @param int $exp 过期时间戳
     * @param int $iat 签发时间戳
     * @param string $jti JWT ID
     * @param array|null $roles 用户角色列表
     * @param array|null $perms 用户权限列表
     * @param array|string|null $customData 自定义数据，可以是数组或加密字符串
     * @return static
     */
    public static function create(
        int $uid,
        string $username,
        string $platform,
        int $exp,
        int $iat,
        string $jti,
        ?array $roles = null,
        ?array $perms = null,
        array|string|null $customData = null
    ): static {
        $custom = [];
        
        // 处理自定义数据
        if (is_string($customData)) {
            // 如果是字符串，将其存储为加密数据
            $custom['encrypted_data'] = $customData;
        } elseif (is_array($customData)) {
            // 如果是数组，直接合并到custom字段
            $custom = $customData;
        }
        
        return new static(
            $uid,
            $username,
            $platform,
            $exp,
            $iat,
            $jti,
            $roles,
            $perms,
            $custom
        );
    }

    /**
     * 检查Token是否已过期
     */
    public function isExpired(): bool
    {
        return time() > $this->exp;
    }

    /**
     * 检查Token是否尚未生效
     */
    public function isNotBefore(): bool
    {
        return isset($this->nbf) && time() < $this->nbf;
    }
    
    /**
     * 获取用户信息数组
     */
    public function getUserInfo(): array
    {
        return [
            'uid' => $this->uid,
            'username' => $this->username,
            'platform' => $this->platform,
            'roles' => $this->roles,
            'perms' => $this->perms,
        ];
    }
    
    /**
     * 获取自定义数据
     * 
     * @param string $key 自定义数据键名
     * @param mixed $default 默认值
     * @return mixed
     */
    public function getCustom(string $key, mixed $default = null): mixed
    {
        return $this->custom[$key] ?? $default;
    }
    
    /**
     * 获取所有自定义数据
     * 
     * @return array
     */
    public function getCustomData(): array
    {
        return $this->custom;
    }
    
    /**
     * 检查是否存在指定的自定义数据
     * 
     * @param string $key 自定义数据键名
     * @return bool
     */
    public function hasCustom(string $key): bool
    {
        return array_key_exists($key, $this->custom);
    }

    /**
     * 获取剩余有效时间（秒）
     */
    public function getTtl(): int
    {
        return max(0, $this->exp - time());
    }

    /**
     * 检查用户是否具有指定角色
     * 
     * @param string $role 角色名称
     * @return bool
     */
    public function hasRole(string $role): bool
    {
        return $this->roles && is_array($this->roles) && in_array($role, $this->roles, true);
    }

    /**
     * 检查用户是否具有指定权限
     * 
     * @param string $permission 权限名称
     * @return bool
     */
    public function hasPermission(string $permission): bool
    {
        return $this->perms && is_array($this->perms) && in_array($permission, $this->perms, true);
    }

    /**
     * 获取用户标识
     */
    public function getUserIdentifier(): string
    {
        return $this->uid . ':' . $this->platform;
    }
    
    /**
     * 获取加密的自定义数据
     * 
     * @return string|null
     */
    public function getEncryptedData(): ?string
    {
        return $this->custom['encrypted_data'] ?? null;
    }
    
    /**
     * 检查是否存在加密的自定义数据
     * 
     * @return bool
     */
    public function hasEncryptedData(): bool
    {
        return isset($this->custom['encrypted_data']);
    }
}