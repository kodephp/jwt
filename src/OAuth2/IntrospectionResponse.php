<?php

declare(strict_types=1);

namespace Kode\Jwt\OAuth2;

use Kode\Jwt\Contract\Arrayable;
use Kode\Jwt\Contract\Jsonable;
use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Token\Payload;

/**
 * Token Introspection 响应（RFC 7662 §2.2）
 *
 * OAuth2 资源服务器通过 introspection 端点查询 Access Token / Refresh Token
 * 当前状态，本类承载响应内容。
 *
 * 必填字段：
 *  - active：Token 是否有效（false 表示已过期/撤销/格式错误）
 *
 * 推荐字段（active=true 时返回，active=false 时不应返回）：
 *  - scope、client_id、username、token_type、exp、iat、nbf、sub、aud、iss、jti
 *
 * 安全说明：
 *  - 资源服务器应在收到 active=false 时立即拒绝请求
 *  - 签发者必须验证请求方客户端身份，避免信息泄露
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7662#section-2.2 RFC 7662 §2.2 - Introspection Response
 */
final readonly class IntrospectionResponse implements Arrayable, Jsonable
{
    /**
     * 私有构造函数，请通过 fromPayload() / inactive() 工厂方法创建
     *
     * @param bool $active 是否有效
     * @param string|null $scope 已授权 scope（空格分隔）
     * @param string|null $clientId 客户端 ID
     * @param string|null $username 用户名
     * @param string|null $tokenType Token 类型（如 "Bearer"）
     * @param int|null $exp 过期时间戳
     * @param int|null $iat 签发时间戳
     * @param int|null $nbf 生效时间戳
     * @param string|null $sub 主体标识
     * @param string|array<string>|null $aud 受众
     * @param string|null $iss 签发者
     * @param string|null $jti JWT ID
     * @param array<string, mixed>|null $extra 额外声明（如 platform / roles / perms）
     */
    public function __construct(
        public bool $active,
        public ?string $scope = null,
        public ?string $clientId = null,
        public ?string $username = null,
        public ?string $tokenType = null,
        public ?int $exp = null,
        public ?int $iat = null,
        public ?int $nbf = null,
        public ?string $sub = null,
        public string|array|null $aud = null,
        public ?string $iss = null,
        public ?string $jti = null,
        public ?array $extra = null,
    ) {
    }

    /**
     * 从 Payload 构造 active=true 的响应
     *
     * @param Payload $payload 已验证的 Payload
     * @param string|null $clientId 客户端 ID（可选）
     * @param string|null $scope scope 字符串（可选，未提供时尝试从 custom 读取）
     * @param string $tokenType Token 类型，默认 "Bearer"
     * @return static
     */
    public static function fromPayload(
        Payload $payload,
        ?string $clientId = null,
        ?string $scope = null,
        string $tokenType = 'Bearer'
    ): static {
        $scope = $scope ?? (is_string($payload->custom['scope'] ?? null)
            ? (string) $payload->custom['scope']
            : null);

        $extra = [
            'platform' => $payload->platform,
        ];
        if ($payload->roles !== null) {
            $extra['roles'] = $payload->roles;
        }
        if ($payload->perms !== null) {
            $extra['perms'] = $payload->perms;
        }
        if ($payload->uid !== null) {
            $extra['uid'] = $payload->uid;
        }

        return new static(
            active: true,
            scope: $scope,
            clientId: $clientId,
            username: $payload->username,
            tokenType: $tokenType,
            exp: $payload->exp,
            iat: $payload->iat,
            nbf: null,
            sub: $payload->subject,
            aud: $payload->audience,
            iss: $payload->issuer,
            jti: $payload->jti,
            extra: $extra,
        );
    }

    /**
     * 构造 active=false 的响应（已过期/已撤销/格式错误）
     *
     * RFC 7662 §2.2.1：active=false 时不应包含其他声明字段。
     *
     * @return static
     */
    public static function inactive(): static
    {
        return new static(active: false);
    }

    /**
     * 判断 Token 是否有效
     *
     * @return bool
     */
    public function isActive(): bool
    {
        return $this->active;
    }

    /**
     * 转为关联数组
     *
     * active=false 时仅返回 {"active": false}；
     * active=true 时返回所有非空字段，键名遵循 RFC 7662。
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function toArray(): array
    {
        if (!$this->active) {
            return ['active' => false];
        }

        $data = ['active' => true];

        // RFC 7662 标准字段
        $fields = [
            'scope'      => $this->scope,
            'client_id'  => $this->clientId,
            'username'   => $this->username,
            'token_type' => $this->tokenType,
            'exp'        => $this->exp,
            'iat'        => $this->iat,
            'nbf'        => $this->nbf,
            'sub'        => $this->sub,
            'aud'        => $this->aud,
            'iss'        => $this->iss,
            'jti'        => $this->jti,
        ];
        foreach ($fields as $key => $value) {
            if ($value !== null && $value !== []) {
                $data[$key] = $value;
            }
        }

        // 额外声明（platform / roles / perms / uid 等）
        if (!empty($this->extra)) {
            foreach ($this->extra as $key => $value) {
                if ($value !== null && $value !== []) {
                    $data[$key] = $value;
                }
            }
        }

        return $data;
    }

    /**
     * 转为 JSON 字符串
     *
     * @param int $options json_encode 选项
     * @return string
     * @throws JwtException 当 JSON 编码失败时
     */
    #[\Override]
    public function toJson(int $options = 0): string
    {
        $options = $options | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        $json = json_encode($this->toArray(), $options);
        if ($json === false) {
            throw new JwtException('Failed to encode introspection response: ' . json_last_error_msg());
        }
        return $json;
    }

    /**
     * 从数组构造（与 toArray 互逆）
     *
     * @param array<string, mixed> $data
     * @return static
     * @throws JwtException 当缺少 active 字段时
     */
    #[\Override]
    public static function fromArray(array $data): static
    {
        if (!array_key_exists('active', $data)) {
            throw new JwtException('IntrospectionResponse 必须包含 active 字段');
        }
        $active = (bool) $data['active'];
        if (!$active) {
            return self::inactive();
        }

        $extra = null;
        $extraKeys = ['platform', 'roles', 'perms', 'uid'];
        $extracted = [];
        foreach ($extraKeys as $key) {
            if (isset($data[$key])) {
                $extracted[$key] = $data[$key];
            }
        }
        if (!empty($extracted)) {
            $extra = $extracted;
        }

        return new static(
            active: true,
            scope: isset($data['scope']) && is_string($data['scope']) ? $data['scope'] : null,
            clientId: isset($data['client_id']) && is_string($data['client_id']) ? $data['client_id'] : null,
            username: isset($data['username']) && is_string($data['username']) ? $data['username'] : null,
            tokenType: isset($data['token_type']) && is_string($data['token_type']) ? $data['token_type'] : null,
            exp: isset($data['exp']) && is_int($data['exp']) ? $data['exp'] : null,
            iat: isset($data['iat']) && is_int($data['iat']) ? $data['iat'] : null,
            nbf: isset($data['nbf']) && is_int($data['nbf']) ? $data['nbf'] : null,
            sub: isset($data['sub']) && is_string($data['sub']) ? $data['sub'] : null,
            aud: $data['aud'] ?? null,
            iss: isset($data['iss']) && is_string($data['iss']) ? $data['iss'] : null,
            jti: isset($data['jti']) && is_string($data['jti']) ? $data['jti'] : null,
            extra: $extra,
        );
    }

    /**
     * 从 JSON 字符串构造
     *
     * @param string $json
     * @return static
     * @throws JwtException
     */
    #[\Override]
    public static function fromJson(string $json): static
    {
        if (!json_validate($json)) {
            throw new JwtException('IntrospectionResponse JSON 解析失败：' . json_last_error_msg());
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new JwtException('IntrospectionResponse JSON 必须为对象');
        }
        return self::fromArray($data);
    }
}
