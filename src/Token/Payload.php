<?php

namespace Kode\Jwt\Token;

use Kode\Jwt\Contract\Arrayable;

final readonly class Payload implements Arrayable
{
    /**
     * Payload构造函数
     *
     * @param int|string|null $uid 用户唯一标识（支持雪花ID等字符串类型）
     * @param string|null $username 用户名
     * @param string $platform 平台标识
     * @param int $exp 过期时间戳
     * @param int $iat 签发时间戳
     * @param string $jti JWT唯一标识
     * @param array<string>|null $roles 角色列表
     * @param array<string>|null $perms 权限列表
     * @param array<string, mixed> $custom 自定义数据
     */
    public function __construct(
        public int|string|null $uid = null,
        public ?string $username = null,
        public string $platform,
        public int $exp,
        public int $iat,
        public string $jti,
        public ?array $roles = null,
        public ?array $perms = null,
        public array $custom = []
    ) {
    }

    public function toArray(): array
    {
        return get_object_vars($this);
    }

    /**
     * 从数组创建Payload实例
     *
     * @param array{
     *     uid?: int|string,
     *     username?: string,
     *     platform: string,
     *     exp: int|string,
     *     iat: int|string,
     *     jti: string,
     *     roles?: array<string>,
     *     perms?: array<string>,
     *     custom?: array<string, mixed>
     * } $data 包含Payload数据的数组
     * @return static
     * @throws \InvalidArgumentException 当必需字段缺失时抛出异常
     */
    public static function fromArray(array $data): static
    {
        // 验证必需字段
        $requiredFields = ['platform', 'exp', 'iat', 'jti'];
        foreach ($requiredFields as $field) {
            if (!isset($data[$field])) {
                throw new \InvalidArgumentException("Missing required field: {$field}");
            }
        }

        return new static(
            $data['uid'] ?? null,
            $data['username'] ?? null,
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
     * @param int|string|null $uid 用户ID（支持雪花ID等字符串类型）
     * @param string|null $username 用户名
     * @param string $platform 平台标识
     * @param int $exp 过期时间戳
     * @param int $iat 签发时间戳
     * @param string $jti JWT ID
     * @param array<string>|null $roles 用户角色列表
     * @param array<string>|null $perms 用户权限列表
     * @param array<string, mixed>|string|null $customData 自定义数据，可以是数组或加密字符串
     * @return static
     */
    public static function create(
        int|string|null $uid = null,
        ?string $username = null,
        string $platform,
        int $exp,
        int $iat,
        string $jti,
        ?array $roles = null,
        ?array $perms = null,
        array|string|null $customData = null
    ): static {
        $custom = [];

        if (is_string($customData)) {
            $custom['encrypted_data'] = $customData;
        } elseif (is_array($customData)) {
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
     * 快速创建Payload（自动处理标准字段和TTL配置）
     *
     * @param array<string, mixed> $userData 用户数据：uid, username, platform, roles, perms, encrypted_data
     * @param array<string, mixed> $config JWT配置（可选，默认从KodeJwt获取）
     * @return static
     *
     * 示例：
     *   // 使用加密数据
     *   $payload = Payload::quickCreate([
     *       'uid' => 'snowflake_id',
     *       'platform' => 'app',
     *       'encrypted_data' => $encryptedUserInfo
     *   ]);
     *
     *   // 使用普通数据
     *   $payload = Payload::quickCreate([
     *       'uid' => 123,
     *       'username' => 'john_doe',
     *       'platform' => 'web',
     *       'roles' => ['admin'],
     *       'perms' => ['read', 'write']
     *   ]);
     */
    public static function quickCreate(array $userData, array $config = []): static
    {
        $now = time();

        $ttl = $config['ttl'] ?? 1440;

        if (isset($config['refresh_ttl'])) {
            $ttl = $config['refresh_ttl'];
        }

        $exp = $now + ($ttl * 60);
        $jti = uniqid('jwt_', true);

        $custom = [];

        if (isset($userData['encrypted_data']) && is_string($userData['encrypted_data'])) {
            $custom['encrypted_data'] = $userData['encrypted_data'];
        } elseif (isset($userData['custom']) && is_array($userData['custom'])) {
            $custom = $userData['custom'];
        }

        return new static(
            $userData['uid'] ?? null,
            $userData['username'] ?? null,
            $userData['platform'] ?? 'default',
            $exp,
            $now,
            $jti,
            $userData['roles'] ?? null,
            $userData['perms'] ?? null,
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
        $nbf = $this->custom['nbf'] ?? null;
        return isset($nbf) && is_int($nbf) && time() < $nbf;
    }

    /**
     * 获取用户信息数组
     *
     * @return array{
     *     uid?: int|string|null,
     *     username?: string|null,
     *     platform: string,
     *     roles?: array<string>|null,
     *     perms?: array<string>|null
     * }
     */
    public function getUserInfo(): array
    {
        return array_filter([
            'uid' => $this->uid,
            'username' => $this->username,
            'platform' => $this->platform,
            'roles' => $this->roles,
            'perms' => $this->perms,
        ], fn($value) => $value !== null);
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
     * @return array<string, mixed>
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
     * 设置加密数据
     *
     * @param string $encryptedData 加密后的数据
     * @return void
     */
    public function setEncryptedData(string $encryptedData): void
    {
        $this->custom['encrypted_data'] = $encryptedData;
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
        return "{$this->uid}:{$this->platform}";
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
