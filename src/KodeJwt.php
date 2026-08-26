<?php

declare(strict_types=1);

namespace Kode\Jwt;

use Kode\Jwt\Claim\ClaimInspector;
use Kode\Jwt\Claim\Confirmation;
use Kode\Jwt\Claim\Scope;
use Kode\Jwt\Config\ConfigLoader;
use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Contract\GuardInterface;
use Kode\Jwt\Contract\LoggerInterface;
use Kode\Jwt\Enum\Algorithm;
use Kode\Jwt\Guard\SsoGuard;
use Kode\Jwt\Guard\MloGuard;
use Kode\Jwt\Key\JwkSet;
use Kode\Jwt\Log\LoggerFactory;
use Kode\Jwt\Log\NullLogger;
use Kode\Jwt\OAuth2\IntrospectionResponse;
use Kode\Jwt\OAuth2\Introspector;
use Kode\Jwt\OAuth2\JwksPublisher;
use Kode\Jwt\OAuth2\RevocationHandler;
use Kode\Jwt\OpenId\DiscoveryConfiguration;
use Kode\Jwt\OpenId\DiscoveryPublisher;
use Kode\Jwt\Policy\TokenPolicy;
use Kode\Jwt\Security\AntiReplay;
use Kode\Jwt\Security\DPoP\DPoPProofBuilder;
use Kode\Jwt\Security\DPoP\DPoPValidator;
use Kode\Jwt\Storage\StorageFactory;
use Kode\Jwt\Key\Jwk;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Parser;
use Kode\Jwt\Event\EventDispatcher;
use Kode\Jwt\Token\Payload;
use Kode\Jwt\Token\TokenManager;

class KodeJwt
{
    private static ?ConfigLoader $configLoader = null;
    private static array $guards = [];
    private static array $storages = [];
    private static ?EventDispatcher $eventDispatcher = null;
    private static ?Parser $parser = null;
    private static ?LoggerInterface $logger = null;
    private static ?AntiReplay $antiReplay = null;
    private static bool $configLoaded = false;

    /**
     * 初始化JWT包并加载用户配置
     */
    public static function init(array $config = []): void
    {
        static::resetRuntimeState();
        static::$configLoader = new ConfigLoader($config);
        static::$eventDispatcher = new EventDispatcher();
        static::$logger = LoggerFactory::create(static::$configLoader->get('logging', []));
        static::bootAntiReplay();
        static::$configLoaded = true;
        static::logger()->info('JWT 初始化完成', ['guard' => static::$configLoader->get('defaults.guard', 'api')]);
    }

    /**
     * 引导防重放保护器
     *
     * 根据配置自动构建 AntiReplay 实例并尝试连接 Redis。
     * 若依赖不可用，降级为关闭状态。
     */
    private static function bootAntiReplay(): void
    {
        if (static::$configLoader === null) {
            static::$antiReplay = null;
            return;
        }

        $replayConfig = static::$configLoader->get('replay', []);
        if (empty($replayConfig) || !is_array($replayConfig)) {
            static::$antiReplay = null;
            return;
        }

        $antiReplay = new AntiReplay($replayConfig);
        try {
            $antiReplay->bootstrapFromConfig(static::$configLoader->all());
        } catch (\Throwable $e) {
            static::logger()->warning('防重放保护初始化失败，已降级为关闭', ['error' => $e->getMessage()]);
            $antiReplay = new AntiReplay(['mode' => AntiReplay::MODE_OFF]);
        }

        static::$antiReplay = $antiReplay;
    }

    /**
     * 获取防重放保护器
     */
    public static function antiReplay(): ?AntiReplay
    {
        if (static::$antiReplay === null && static::$configLoader !== null) {
            static::bootAntiReplay();
        }
        return static::$antiReplay;
    }

    /**
     * 从文件加载配置
     */
    public static function loadConfigFromFile(string $path): void
    {
        if (!file_exists($path)) {
            throw new \InvalidArgumentException("配置文件不存在: {$path}");
        }

        $config = require $path;

        if (!is_array($config)) {
            throw new \InvalidArgumentException("配置文件必须返回数组: {$path}");
        }

        static::init($config);
        static::logger()->info('JWT 配置文件加载成功', ['path' => $path]);
    }

    /**
     * 自动检测并加载配置文件
     *
     * 支持的常见框架配置路径:
     * - Laravel: base_path()/config/jwt.php
     * - Hyperf: BASE_PATH . '/config/jwt.php'
     * - ThinkPHP: root_path() . 'config/jwt.php'
     * - Yii2: @app/config/jwt.php
     * - Symfony: config/jwt.php
     * - 通用: config/jwt.php, app/config/jwt.php
     */
    public static function detectAndLoadConfig(): bool
    {
        $basePaths = static::detectFrameworkPaths();
        $configFiles = ['config/jwt.php', 'app/config/jwt.php', 'config/autoload/jwt.php'];

        foreach ($basePaths as $basePath) {
            foreach ($configFiles as $configFile) {
                $fullPath = $basePath . '/' . $configFile;
                if (file_exists($fullPath)) {
                    static::loadConfigFromFile($fullPath);
                    static::logger()->debug('自动检测到 JWT 配置文件', ['path' => $fullPath]);
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 检测当前运行环境可能的框架根目录
     */
    private static function detectFrameworkPaths(): array
    {
        $paths = [];

        $currentDir = getcwd() ?? dirname(__DIR__);
        $paths[] = $currentDir;

        $parentDir = dirname($currentDir);
        if ($parentDir !== $currentDir) {
            $paths[] = $parentDir;
        }

        $envPaths = [
            'LARAVEL_BASE_PATH' => null,
            'BASE_PATH' => null,
            'APP_PATH' => null,
            'YII2_APP_PATH' => null,
            'APPLICATION_PATH' => null,
            'ROOT_PATH' => null,
        ];

        foreach ($envPaths as $envKey => &$value) {
            $value = getenv($envKey) ?: (isset($_ENV[$envKey]) ? $_ENV[$envKey] : null);
            if ($value && is_dir($value)) {
                $paths[] = realpath($value);
            }
        }

        return array_unique(array_filter($paths, fn($p) => $p && is_dir($p)));
    }

    /**
     * 获取框架类型猜测
     */
    public static function getFrameworkType(): string
    {
        $basePaths = static::detectFrameworkPaths();

        foreach ($basePaths as $basePath) {
            if (file_exists($basePath . '/artisan')) {
                return 'laravel';
            }
            if (file_exists($basePath . '/bin/hyperf.php')) {
                return 'hyperf';
            }
            if (file_exists($basePath . '/think')) {
                return 'thinkphp';
            }
            if (file_exists($basePath . '/config/app.php')) {
                return 'yii2';
            }
            if (file_exists($basePath . '/config/services.yaml')) {
                return 'symfony';
            }
        }

        return 'unknown';
    }

    /**
     * 创建针对特定框架的配置路径
     */
    public static function getFrameworkConfigPath(string $framework, string $filename = 'jwt.php'): string
    {
        $basePaths = static::detectFrameworkPaths();
        $basePath = $basePaths[0] ?? getcwd();

        return match ($framework) {
            'laravel' => $basePath . '/config/' . $filename,
            'hyperf' => $basePath . '/config/' . $filename,
            'thinkphp' => $basePath . '/config/' . $filename,
            'yii2' => $basePath . '/config/' . $filename,
            'symfony' => $basePath . '/config/' . $filename,
            default => $basePath . '/config/' . $filename,
        };
    }

    /**
     * 检查配置是否已加载
     */
    public static function isConfigLoaded(): bool
    {
        return static::$configLoaded || static::$configLoader !== null;
    }

    /**
     * 获取默认配置
     */
    public static function getDefaultConfig(): array
    {
        return [
            'defaults' => [
                'guard' => 'api',
                'storage' => 'memory',
            ],
            'guards' => [
                'api' => [
                    'driver' => 'sso',
                    'storage' => 'memory',
                    'algo' => 'HS256',
                    // 使用 HMAC 算法时必须配置非空密钥
                    'secret' => '',
                    'ttl' => 3600,
                    'refresh_ttl' => 604800,
                    'blacklist_enabled' => true,
                    'blacklist_ttl' => 604800,
                    'platform' => null,
                    'single_login' => false,
                    // 时钟漂移容忍（秒），用于跨节点 NTP 偏差场景
                    'clock_skew' => 30,
                    // 期望的标准声明（iss/aud/sub），Parser 会强制匹配
                    'expected_claims' => [],
                ],
            ],
            'storage' => [
                'memory' => [
                    'driver' => 'memory',
                ],
                'redis' => [
                    'driver' => 'redis',
                    'host' => '127.0.0.1',
                    'port' => 6379,
                    'password' => null,
                    'database' => 0,
                    'prefix' => 'kode:jwt:',
                    'ttl' => 0,
                    'persistent' => false,
                    'persistent_id' => 'kode_jwt_redis',
                ],
            ],
            'logging' => [
                'enabled' => false,
                'driver' => 'file',
                'path' => './logs/kode-jwt.log',
                'level' => 'info',
            ],
            'replay' => [
                'mode' => 'off',
                'require_nonce' => false,
                'window' => 60,
                'max_requests' => 5,
                'backend' => 'redis',
                'redis_storage' => 'redis',
                'prefix' => 'kode:jwt:',
                'ttl' => 3600,
            ],
        ];
    }

    /**
     * 获取配置加载器
     */
    public static function config(): ConfigLoader
    {
        if (static::$configLoader === null) {
            static::init();
        }

        return static::$configLoader;
    }

    /**
     * 获取事件分发器
     */
    public static function events(): EventDispatcher
    {
        if (static::$eventDispatcher === null) {
            static::$eventDispatcher = new EventDispatcher();
        }

        return static::$eventDispatcher;
    }

    /**
     * 获取日志实例
     *
     * 在未启用日志配置时返回空日志对象，确保调用端无条件可用。
     */
    public static function logger(): LoggerInterface
    {
        if (static::$logger !== null) {
            return static::$logger;
        }

        if (static::$configLoader !== null) {
            static::$logger = LoggerFactory::create(static::$configLoader->get('logging', []));
            return static::$logger;
        }

        static::$logger = new NullLogger();
        return static::$logger;
    }

    /**
     * 获取一个全新的 Token 构建器实例
     *
     * ⚠️ 每次调用都返回全新的、状态隔离的 Builder 实例。
     * Builder 是可变对象（setClaim/setClaims 会累积状态），
     * 跨请求复用同一个实例会泄漏前次 claims、碰撞 jti。
     * 因此这里刻意不缓存单例。需复用同一实例时，请调用 Builder::reset()。
     *
     * 推荐通过 KodeJwt::guard($g)->issue(new Payload(...)) 签发 Token。
     */
    public static function builder(): Builder
    {
        return new Builder(static::config()->get('guards.api', []));
    }

    /**
     * 获取Token解析器
     */
    public static function parser(): Parser
    {
        if (static::$parser === null) {
            static::$parser = new Parser(static::config()->get('guards.api', []));
        }

        return static::$parser;
    }

    /**
     * 获取存储实例
     */
    public static function storage(?string $name = null): StorageInterface
    {
        $name = $name ?? static::config()->get('defaults.storage', 'memory');

        if (!isset(static::$storages[$name])) {
            $factory = new StorageFactory(static::config());
            static::$storages[$name] = $factory->create($name);
            static::logger()->debug('存储实例创建完成', ['storage' => $name]);
        }

        return static::$storages[$name];
    }

    /**
     * 获取守卫实例
     */
    public static function guard(?string $name = null): GuardInterface
    {
        $name = $name ?? static::config()->get('defaults.guard', 'api');

        $availableGuards = array_keys(static::config()->get('guards', []));

        if (!in_array($name, $availableGuards, true) && $name !== 'api') {
            throw new JwtException("Guard [{$name}] is not configured. Available guards: " . implode(', ', $availableGuards));
        }

        if (!isset(static::$guards[$name])) {
            $guardConfig = static::config()->get("guards.{$name}", []);
            $storage = static::storage($guardConfig['storage'] ?? 'memory');

            // 创建Builder和Parser实例
            $builder = new Builder($guardConfig);
            $parser = new Parser($guardConfig);

            // 根据驱动类型创建守卫
            switch ($guardConfig['driver'] ?? 'sso') {
                case 'mlo':
                    $guard = new MloGuard(
                        $storage,
                        $builder,
                        $parser,
                        static::events(),
                        static::logger(),
                        $guardConfig
                    );
                    break;
                case 'sso':
                default:
                    $guard = new SsoGuard(
                        $storage,
                        $builder,
                        $parser,
                        static::events(),
                        static::logger(),
                        $guardConfig
                    );
                    break;
            }

            // 注入防重放保护
            if (static::$antiReplay !== null && method_exists($guard, 'withAntiReplay')) {
                $guard->withAntiReplay(static::$antiReplay);
            }

            static::$guards[$name] = $guard;
            static::logger()->info('守卫实例创建完成', ['guard' => $name, 'driver' => $guardConfig['driver'] ?? 'sso']);
        }

        return static::$guards[$name];
    }

    /**
     * 快速签发Token
     */
    public static function issue(Payload $payload, ?string $guard = null): array
    {
        return static::guard($guard)->issue($payload);
    }

    /**
     * 快速验证Token
     */
    public static function authenticate(string $token, ?string $guard = null): Payload
    {
        return static::guard($guard)->authenticate($token);
    }

    /**
     * 快速刷新Token
     */
    public static function refresh(string $token, ?string $guard = null): array
    {
        return static::guard($guard)->refresh($token);
    }

    /**
     * 快速注销Token
     */
    public static function invalidate(string $token, ?string $guard = null): bool
    {
        return static::guard($guard)->invalidate($token);
    }

    /**
     * 清理过期的Token
     */
    public static function cleanExpired(?string $storage = null): int
    {
        $result = static::storage($storage)->cleanExpired();
        if (is_int($result)) {
            return $result;
        }

        return $result ? 1 : 0;
    }

    /**
     * 获取存储统计信息
     */
    public static function getStats(?string $storage = null): array
    {
        return static::storage($storage)->getStats();
    }

    /**
     * 获取Token管理器
     */
    public static function tokenManager(?string $guard = null): TokenManager
    {
        // 统一使用解析后的 $guardName，避免 $guard=null 时配置读取与守卫实例使用的 guard 不一致
        $guardName = $guard ?? static::config()->get('defaults.guard', 'api');
        $guardConfig = static::config()->get("guards.{$guardName}", []);
        $storageName = (string) ($guardConfig['storage'] ?? static::config()->get('defaults.storage', 'memory'));
        $guardInstance = static::guard($guardName);

        return new TokenManager(
            static::storage($storageName),
            $guardInstance,
            static::config()
        );
    }

    /**
     * 获取用户的所有活跃Token
     */
    public static function getUserTokens(string $uid, ?string $platform = null, ?string $guard = null): array
    {
        return static::tokenManager($guard)->getUserTokens($uid, $platform);
    }

    /**
     * 强制注销用户的所有Token
     */
    public static function revokeUserTokens(string $uid, ?string $platform = null, ?string $guard = null): int
    {
        return static::tokenManager($guard)->revokeUserTokens($uid, $platform);
    }

    /**
     * 检查Token是否有效
     */
    public static function isTokenValid(string $token, ?string $guard = null): bool
    {
        return static::tokenManager($guard)->isTokenValid($token);
    }

    /**
     * 获取Token信息
     */
    public static function getTokenInfo(string $token, ?string $guard = null): ?array
    {
        return static::tokenManager($guard)->getTokenInfo($token);
    }

    /**
     * 按完整 Token 撤销（将 jti 加入黑名单，RFC 7009）
     *
     * 内部走 RevocationHandler：解析验签 → 取 jti → 以「距过期剩余时间」为 TTL 加入黑名单。
     * 遵循 RFC 7009 侧通道防护：解析/验签失败或 Token 无 jti，均视为「已撤销」返回 true，
     * 不泄露 Token 是否存在/有效。
     *
     * @param string $token 待撤销的 Token
     * @param string|null $guard 守卫名称，传 null 使用默认守卫
     * @return bool 撤销请求已被接受（true）
     */
    public static function revokeToken(string $token, ?string $guard = null): bool
    {
        return static::revocation($guard)->revoke($token)->isRevoked();
    }

    /**
     * 直接按 jti 撤销 Token（将 jti 加入黑名单）
     *
     * 适用于仅有 jti（如来自审计日志、外部系统回调）的场景，无需持有原始 Token。
     *
     * @param string $jti JWT ID
     * @param int $ttl 黑名单保留时间（秒），默认 3600
     * @param string|null $guard 守卫名称，传 null 使用默认守卫
     * @return bool
     */
    public static function revokeJti(string $jti, int $ttl = 3600, ?string $guard = null): bool
    {
        return static::storageForGuard($guard)->blacklist($jti, $ttl);
    }

    /**
     * 判断 jti 是否已被撤销（命中黑名单）
     *
     * @param string $jti JWT ID
     * @param string|null $guard 守卫名称，传 null 使用默认守卫
     * @return bool
     */
    public static function isBlacklisted(string $jti, ?string $guard = null): bool
    {
        return static::storageForGuard($guard)->isBlacklisted($jti);
    }

    /**
     * 将 jti 从黑名单中移除（撤销恢复）
     *
     * 用于管理员误撤销后恢复 Token 有效性。仅移除黑名单记录，
     * 不影响已过期（exp）或 SSO 映射等其他状态。
     *
     * @param string $jti JWT ID
     * @param string|null $guard 守卫名称，传 null 使用默认守卫
     * @return bool
     */
    public static function unblacklist(string $jti, ?string $guard = null): bool
    {
        return static::storageForGuard($guard)->removeFromBlacklist($jti);
    }

    /**
     * 解析某守卫对应的存储实例
     *
     * 统一从 guard 配置推导其 storage 名称，避免多处重复推导导致不一致。
     */
    private static function storageForGuard(?string $guard): StorageInterface
    {
        $guardName = $guard ?? static::config()->get('defaults.guard', 'api');
        $guardConfig = static::config()->get("guards.{$guardName}", []);
        $storageName = (string) ($guardConfig['storage'] ?? static::config()->get('defaults.storage', 'memory'));

        return static::storage($storageName);
    }

    /**
     * 创建 JWKS 端点发布器
     *
     * 用于 OAuth2 资源服务器 / OIDC 依赖方通过 jwks_uri 拉取验签公钥。
     *
     * @param JwkSet $jwkSet 待发布的 JWK Set（可包含私钥，发布时自动剥离）
     * @param int $maxAge Cache-Control max-age（秒），默认 3600
     * @return JwksPublisher
     */
    public static function jwksPublisher(JwkSet $jwkSet, int $maxAge = 3600): JwksPublisher
    {
        return new JwksPublisher($jwkSet, $maxAge);
    }

    /**
     * 创建 Token Introspector（RFC 7662）
     *
     * 用于资源服务器查询 Token 当前状态。默认使用配置中的默认 guard 的
     * Parser 与 Storage 实例。
     *
     * @param string|null $guard 守卫名称，传 null 使用默认守卫
     * @return Introspector
     */
    public static function introspector(?string $guard = null): Introspector
    {
        $guardName = $guard ?? static::config()->get('defaults.guard', 'api');
        $guardConfig = static::config()->get("guards.{$guardName}", []);
        $storageName = (string) ($guardConfig['storage']
            ?? static::config()->get('defaults.storage', 'memory'));

        return new Introspector(
            static::parser(),
            static::storage($storageName),
            static::logger()
        );
    }

    /**
     * 内省 Token 当前状态（便捷方法）
     *
     * @param string $token 待查询的 Token
     * @param string|null $expectedPlatform 期望的平台标识
     * @param string|null $clientId 资源方客户端 ID
     * @param string|null $guard 守卫名称
     * @return IntrospectionResponse
     */
    public static function introspect(
        string $token,
        ?string $expectedPlatform = null,
        ?string $clientId = null,
        ?string $guard = null,
    ): IntrospectionResponse {
        return static::introspector($guard)->introspect($token, $expectedPlatform, $clientId);
    }

    /**
     * 创建 OIDC Discovery 配置
     *
     * @param string $issuer 签发者标识
     * @param string $authorizationEndpoint 授权端点
     * @param string $tokenEndpoint Token 端点
     * @param string $jwksUri JWKS 公钥端点
     * @param array<string, mixed> $extra 额外字段
     * @return DiscoveryConfiguration
     */
    public static function discoveryConfiguration(
        string $issuer,
        string $authorizationEndpoint,
        string $tokenEndpoint,
        string $jwksUri,
        array $extra = [],
    ): DiscoveryConfiguration {
        return new DiscoveryConfiguration(
            issuer: $issuer,
            authorizationEndpoint: $authorizationEndpoint,
            tokenEndpoint: $tokenEndpoint,
            jwksUri: $jwksUri,
            extra: $extra,
        );
    }

    /**
     * 创建 OIDC Discovery 端点发布器
     *
     * @param DiscoveryConfiguration $configuration Discovery 元数据
     * @param int $maxAge Cache-Control max-age（秒）
     * @return DiscoveryPublisher
     */
    public static function discoveryPublisher(
        DiscoveryConfiguration $configuration,
        int $maxAge = 3600,
    ): DiscoveryPublisher {
        return new DiscoveryPublisher($configuration, $maxAge);
    }

    /**
     * 创建空 Token 策略
     *
     * @return TokenPolicy
     */
    public static function tokenPolicy(): TokenPolicy
    {
        return TokenPolicy::create();
    }

    /**
     * 创建 Claim 检查器
     *
     * @return ClaimInspector
     */
    public static function claimInspector(): ClaimInspector
    {
        return new ClaimInspector();
    }

    /**
     * 从空格分隔字符串创建 Scope 值对象
     *
     * @param string $scopeString
     * @return Scope
     */
    public static function scope(string $scopeString): Scope
    {
        return Scope::fromString($scopeString);
    }

    /**
     * 创建确认声明（cnf）— RFC 7800
     *
     * 将 Token 与密钥绑定，典型用于 DPoP（RFC 9449）：
     * 传入公钥或私钥 JWK，自动取公钥并计算 RFC 7638 指纹（jkt）。
     *
     * @param Jwk $jwk 用于绑定的密钥（公钥或私钥 JWK 均可）
     * @return Confirmation
     */
    public static function confirmationFromJwk(Jwk $jwk): Confirmation
    {
        return Confirmation::withJwk($jwk);
    }

    /**
     * 创建 DPoP 证明构建器（RFC 9449）
     *
     * @param Algorithm $algorithm 非对称签名算法（推荐 EdDSA / ES256）
     * @param string $privateKeyPem 私钥 PEM 或文件路径
     * @param string|null $kid 可选密钥标识
     * @return DPoPProofBuilder
     */
    public static function dpopBuilder(Algorithm $algorithm, string $privateKeyPem, ?string $kid = null): DPoPProofBuilder
    {
        return new DPoPProofBuilder($algorithm, $privateKeyPem, $kid);
    }

    /**
     * 创建 DPoP 证明校验器（RFC 9449）
     *
     * @param int $maxAge iat 新鲜度窗口（秒），默认 300
     * @param string|null $expectedNonce 服务端下发的 nonce（可选，强制匹配）
     * @param string|null $expectedAth 绑定的 Access Token 哈希（可选，强制匹配）
     * @return DPoPValidator
     */
    public static function dpopValidator(int $maxAge = 300, ?string $expectedNonce = null, ?string $expectedAth = null): DPoPValidator
    {
        return new DPoPValidator($maxAge, $expectedNonce, $expectedAth);
    }

    /**
     * 创建 Token 撤销处理器（RFC 7009）
     *
     * 将 Token 的 jti 加入黑名单，与 introspection / guard 共用存储，
     * 被撤销的 Token 在后续鉴权中立即失效。
     *
     * @param string|null $guard 守卫名称，传 null 使用默认守卫的 Parser 与 Storage
     * @return RevocationHandler
     */
    public static function revocation(?string $guard = null): RevocationHandler
    {
        $guardName = $guard ?? static::config()->get('defaults.guard', 'api');
        $guardConfig = static::config()->get("guards.{$guardName}", []);
        $storageName = (string) ($guardConfig['storage'] ?? static::config()->get('defaults.storage', 'memory'));

        return new RevocationHandler(
            static::parser(),
            static::storage($storageName),
            static::logger()
        );
    }

    /**
     * 重置运行时缓存状态
     *
     * 用于配置重载场景，确保 Guard、Storage、Builder、Parser 与最新配置一致。
     */
    private static function resetRuntimeState(): void
    {
        static::$guards = [];
        static::$storages = [];
        static::$parser = null;
        static::$logger = null;
        static::$antiReplay = null;
    }
}
