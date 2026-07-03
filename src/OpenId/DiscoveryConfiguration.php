<?php

declare(strict_types=1);

namespace Kode\Jwt\OpenId;

use Kode\Jwt\Contract\Arrayable;
use Kode\Jwt\Contract\Jsonable;
use Kode\Jwt\Exception\JwtException;

/**
 * OIDC / OAuth2 Discovery 元数据（RFC 8414）
 *
 * 用于发布授权服务器的能力元数据，让依赖方（RP）能自动发现：
 *  - authorization_endpoint / token_endpoint / introspection_endpoint
 *  - jwks_uri（验签公钥位置）
 *  - 支持的 scopes / response_types / grant_types / subject_types
 *  - 支持的签名算法 id_token_signing_alg_values_supported
 *  - claims_supported（OIDC 标准）
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8414 RFC 8414 - OAuth 2.0 Authorization Server Metadata
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html OIDC Discovery 1.0
 */
final readonly class DiscoveryConfiguration implements Arrayable, Jsonable
{
    /**
     * 默认支持的 scopes
     */
    private const array DEFAULT_SCOPES_SUPPORTED = ['openid', 'profile', 'email', 'offline_access'];

    /**
     * 默认支持的 response_type
     */
    private const array DEFAULT_RESPONSE_TYPES_SUPPORTED = ['code', 'token', 'id_token'];

    /**
     * 默认支持的 grant_type
     */
    private const array DEFAULT_GRANT_TYPES_SUPPORTED = [
        'authorization_code',
        'implicit',
        'refresh_token',
        'client_credentials',
    ];

    /**
     * 默认支持的 subject_type
     */
    private const array DEFAULT_SUBJECT_TYPES_SUPPORTED = ['public'];

    /**
     * 默认支持的 id_token 签名算法
     */
    private const array DEFAULT_ID_TOKEN_ALGS_SUPPORTED = ['RS256', 'RS384', 'RS512', 'HS256'];

    /**
     * 默认支持的 claims
     */
    private const array DEFAULT_CLAIMS_SUPPORTED = [
        'sub', 'iss', 'aud', 'exp', 'iat', 'nbf', 'jti', 'nonce', 'auth_time',
        'acr', 'amr', 'azp', 'at_hash', 'c_hash', 'scope',
        'uid', 'username', 'platform', 'roles', 'perms',
    ];

    /**
     * 构造函数
     *
     * @param string $issuer 签发者标识（必须为 HTTPS URL，且作为 metadata 文档的 issuer 字段）
     * @param string $authorizationEndpoint 授权端点 URL
     * @param string $tokenEndpoint Token 端点 URL
     * @param string $jwksUri JWKS 公钥端点 URL
     * @param string|null $userinfoEndpoint UserInfo 端点 URL（OIDC）
     * @param string|null $introspectionEndpoint Introspection 端点 URL（RFC 7662）
     * @param string|null $revocationEndpoint 撤销端点 URL（RFC 7009）
     * @param string|null $endSessionEndpoint 登出端点 URL（OIDC）
     * @param array<string> $scopesSupported 支持的 scopes
     * @param array<string> $responseTypesSupported 支持的 response_type
     * @param array<string> $grantTypesSupported 支持的 grant_type
     * @param array<string> $subjectTypesSupported 支持的 subject_type
     * @param array<string> $idTokenSigningAlgValuesSupported 支持的 id_token 签名算法
     * @param array<string> $claimsSupported 支持的 claims
     * @param array<string, mixed> $extra 额外字段（如 require_auth_time、code_challenge_methods_supported）
     */
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
        public ?string $userinfoEndpoint = null,
        public ?string $introspectionEndpoint = null,
        public ?string $revocationEndpoint = null,
        public ?string $endSessionEndpoint = null,
        public array $scopesSupported = self::DEFAULT_SCOPES_SUPPORTED,
        public array $responseTypesSupported = self::DEFAULT_RESPONSE_TYPES_SUPPORTED,
        public array $grantTypesSupported = self::DEFAULT_GRANT_TYPES_SUPPORTED,
        public array $subjectTypesSupported = self::DEFAULT_SUBJECT_TYPES_SUPPORTED,
        public array $idTokenSigningAlgValuesSupported = self::DEFAULT_ID_TOKEN_ALGS_SUPPORTED,
        public array $claimsSupported = self::DEFAULT_CLAIMS_SUPPORTED,
        public array $extra = [],
    ) {
        if ($issuer === '') {
            throw new JwtException('DiscoveryConfiguration issuer 不能为空');
        }
        if ($authorizationEndpoint === '' || $tokenEndpoint === '' || $jwksUri === '') {
            throw new JwtException('DiscoveryConfiguration 必填端点不能为空');
        }
    }

    /**
     * 从数组构造
     *
     * @param array<string, mixed> $data
     * @return static
     */
    #[\Override]
    public static function fromArray(array $data): static
    {
        $required = ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'];
        foreach ($required as $field) {
            if (!isset($data[$field]) || !is_string($data[$field]) || $data[$field] === '') {
                throw new JwtException("DiscoveryConfiguration 缺失或非法字段：{$field}");
            }
        }

        // 提取 extra 字段（非标准字段）
        $standardKeys = [
            'issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri',
            'userinfo_endpoint', 'introspection_endpoint', 'revocation_endpoint', 'end_session_endpoint',
            'scopes_supported', 'response_types_supported', 'grant_types_supported',
            'subject_types_supported', 'id_token_signing_alg_values_supported', 'claims_supported',
        ];
        $extra = $data['extra'] ?? [];
        if (!is_array($extra)) {
            $extra = [];
        }
        foreach ($data as $key => $value) {
            if (!in_array($key, $standardKeys, true) && $key !== 'extra') {
                $extra[$key] = $value;
            }
        }

        return new static(
            issuer: $data['issuer'],
            authorizationEndpoint: $data['authorization_endpoint'],
            tokenEndpoint: $data['token_endpoint'],
            jwksUri: $data['jwks_uri'],
            userinfoEndpoint: $data['userinfo_endpoint'] ?? null,
            introspectionEndpoint: $data['introspection_endpoint'] ?? null,
            revocationEndpoint: $data['revocation_endpoint'] ?? null,
            endSessionEndpoint: $data['end_session_endpoint'] ?? null,
            scopesSupported: $data['scopes_supported'] ?? self::DEFAULT_SCOPES_SUPPORTED,
            responseTypesSupported: $data['response_types_supported'] ?? self::DEFAULT_RESPONSE_TYPES_SUPPORTED,
            grantTypesSupported: $data['grant_types_supported'] ?? self::DEFAULT_GRANT_TYPES_SUPPORTED,
            subjectTypesSupported: $data['subject_types_supported'] ?? self::DEFAULT_SUBJECT_TYPES_SUPPORTED,
            idTokenSigningAlgValuesSupported: $data['id_token_signing_alg_values_supported']
                ?? self::DEFAULT_ID_TOKEN_ALGS_SUPPORTED,
            claimsSupported: $data['claims_supported'] ?? self::DEFAULT_CLAIMS_SUPPORTED,
            extra: $extra,
        );
    }

    /**
     * 从 JSON 字符串构造
     *
     * @param string $json
     * @return static
     * @throws JwtException 当 JSON 格式错误时
     */
    #[\Override]
    public static function fromJson(string $json): static
    {
        if (!json_validate($json)) {
            throw new JwtException('DiscoveryConfiguration JSON 解析失败：' . json_last_error_msg());
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new JwtException('DiscoveryConfiguration JSON 必须为对象');
        }
        return self::fromArray($data);
    }

    /**
     * 转为关联数组
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function toArray(): array
    {
        $data = [
            'issuer'                                => $this->issuer,
            'authorization_endpoint'                => $this->authorizationEndpoint,
            'token_endpoint'                        => $this->tokenEndpoint,
            'jwks_uri'                              => $this->jwksUri,
            'scopes_supported'                      => $this->scopesSupported,
            'response_types_supported'              => $this->responseTypesSupported,
            'grant_types_supported'                 => $this->grantTypesSupported,
            'subject_types_supported'               => $this->subjectTypesSupported,
            'id_token_signing_alg_values_supported' => $this->idTokenSigningAlgValuesSupported,
            'claims_supported'                      => $this->claimsSupported,
        ];

        // 可选字段
        $optional = [
            'userinfo_endpoint'       => $this->userinfoEndpoint,
            'introspection_endpoint'  => $this->introspectionEndpoint,
            'revocation_endpoint'     => $this->revocationEndpoint,
            'end_session_endpoint'    => $this->endSessionEndpoint,
        ];
        foreach ($optional as $key => $value) {
            if ($value !== null && $value !== '') {
                $data[$key] = $value;
            }
        }

        // 额外字段
        foreach ($this->extra as $key => $value) {
            if ($value !== null && $value !== []) {
                $data[$key] = $value;
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
            throw new JwtException('DiscoveryConfiguration JSON 编码失败：' . json_last_error_msg());
        }
        return $json;
    }
}
