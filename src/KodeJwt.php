<?php

namespace Kode\Jwt;

use Kode\Jwt\Config\ConfigLoader;
use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Contract\GuardInterface;
use Kode\Jwt\Guard\SsoGuard;
use Kode\Jwt\Guard\MloGuard;
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
    private static bool $configLoaded = false;

    /**
     * 初始化JWT包并加载用户配置
     */
    public static function init(array $config = []): void
    {
        if (!empty($config)) {
            static::$configLoader = new ConfigLoader($config);
        } else {
            static::$configLoader = new ConfigLoader();
        }
        static::$eventDispatcher = new EventDispatcher();
        static::$configLoaded = true;
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
                    'secret' => 'your-256-bit-secret-key-here',
                    'ttl' => 3600,
                    'refresh_ttl' => 604800,
                    'blacklist_enabled' => true,
                    'blacklist_ttl' => 604800,
                    'platform' => null,
                    'single_login' => false,
                ],
            ],
            'storages' => [
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
                ],
            ],
        ];
    }

    /**
     * 获取配置加载器
     */
    public static function config(): ConfigLoader
    {
        if (static::$configLoader === null) {
            static::$configLoader = new ConfigLoader();
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
    public static function storage(string $name = null): StorageInterface
    {
        $name = $name ?? static::config()->get('defaults.storage', 'memory');

        if (!isset(static::$storages[$name])) {
            $factory = new StorageFactory(static::config());
            static::$storages[$name] = $factory->create($name);
        }

        return static::$storages[$name];
    }

    /**
     * 获取守卫实例
     */
    public static function guard(string $name = null): GuardInterface
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
                    static::$guards[$name] = new MloGuard($storage, $builder, $parser, static::events(), $guardConfig);
                    break;
                case 'sso':
                default:
                    static::$guards[$name] = new SsoGuard($storage, $builder, $parser, static::events(), $guardConfig);
                    break;
            }
        }

        return static::$guards[$name];
    }

    /**
     * 快速签发Token
     */
    public static function issue(Payload $payload, string $guard = null): array
    {
        return static::guard($guard)->issue($payload);
    }

    /**
     * 快速验证Token
     */
    public static function authenticate(string $token, string $guard = null): Payload
    {
        return static::guard($guard)->authenticate($token);
    }

    /**
     * 快速刷新Token
     */
    public static function refresh(string $token, string $guard = null): array
    {
        return static::guard($guard)->refresh($token);
    }

    /**
     * 快速注销Token
     */
    public static function invalidate(string $token, string $guard = null): bool
    {
        return static::guard($guard)->invalidate($token);
    }

    /**
     * 清理过期的Token
     */
    public static function cleanExpired(string $storage = null): int
    {
        return static::storage($storage)->cleanExpired();
    }

    /**
     * 获取存储统计信息
     */
    public static function getStats(string $storage = null): array
    {
        return static::storage($storage)->getStats();
    }

    /**
     * 获取Token管理器
     */
    public static function tokenManager(string $guard = null): TokenManager
    {
        $guardInstance = static::guard($guard);
        return new TokenManager(
            static::storage(),
            $guardInstance,
            static::config()
        );
    }

    /**
     * 获取用户的所有活跃Token
     */
    public static function getUserTokens(string $uid, string $platform = null, string $guard = null): array
    {
        return static::tokenManager($guard)->getUserTokens($uid, $platform);
    }

    /**
     * 强制注销用户的所有Token
     */
    public static function revokeUserTokens(string $uid, string $platform = null, string $guard = null): int
    {
        return static::tokenManager($guard)->revokeUserTokens($uid, $platform);
    }

    /**
     * 检查Token是否有效
     */
    public static function isTokenValid(string $token, string $guard = null): bool
    {
        return static::tokenManager($guard)->isTokenValid($token);
    }

    /**
     * 获取Token信息
     */
    public static function getTokenInfo(string $token, string $guard = null): ?array
    {
        return static::tokenManager($guard)->getTokenInfo($token);
    }
}
