<?php

declare(strict_types=1);

namespace Kode\Jwt;

use Kode\Jwt\Config\ConfigLoader;
use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Contract\GuardInterface;
use Kode\Jwt\Contract\LoggerInterface;
use Kode\Jwt\Guard\SsoGuard;
use Kode\Jwt\Guard\MloGuard;
use Kode\Jwt\Log\LoggerFactory;
use Kode\Jwt\Log\NullLogger;
use Kode\Jwt\Security\AntiReplay;
use Kode\Jwt\Storage\StorageFactory;
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
    private static ?Builder $builder = null;
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
     * 获取Token构建器
     */
    public static function builder(): Builder
    {
        if (static::$builder === null) {
            static::$builder = new Builder(static::config()->get('guards.api', []));
        }

        return static::$builder;
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
        $guardName = $guard ?? static::config()->get('defaults.guard', 'api');
        $guardConfig = static::config()->get("guards.{$guardName}", []);
        $storageName = (string) ($guardConfig['storage'] ?? static::config()->get('defaults.storage', 'memory'));
        $guardInstance = static::guard($guard);

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
     * 重置运行时缓存状态
     *
     * 用于配置重载场景，确保 Guard、Storage、Builder、Parser 与最新配置一致。
     */
    private static function resetRuntimeState(): void
    {
        static::$guards = [];
        static::$storages = [];
        static::$builder = null;
        static::$parser = null;
        static::$logger = null;
        static::$antiReplay = null;
    }
}
