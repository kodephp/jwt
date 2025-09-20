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
    
    /**
     * 初始化JWT包
     */
    public static function init(array $config = []): void
    {
        static::$configLoader = new ConfigLoader($config);
        static::$eventDispatcher = new EventDispatcher();
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