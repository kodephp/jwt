<?php

namespace Kode\Jwt\Config;

class ConfigLoader
{
    private array $config;
    
    public function __construct(array $config = [])
    {
        $this->config = array_merge($this->getDefaultConfig(), $config);
    }
    
    /**
     * 获取默认配置
     */
    private function getDefaultConfig(): array
    {
        return [
            'defaults' => [
                'guard' => 'api',
                'provider' => 'users',
            ],
            
            'guards' => [
                'api' => [
                    'driver' => 'kode',
                    'provider' => 'users',
                    'storage' => 'redis',
                    'blacklist_enabled' => true,
                    'refresh_enabled' => true,
                    'refresh_ttl' => 20160,
                    'ttl' => 1440,
                    'algo' => 'HS256',
                    'secret' => '',
                    'public_key' => '',
                    'private_key' => '',
                ],
            ],
            
            'platforms' => [
                'web', 'h5', 'pc', 'app', 'wx_mini', 'ali_mini', 'tt_mini'
            ],
            
            'storage' => [
                'redis' => [
                    'host' => '127.0.0.1',
                    'port' => 6379,
                    'password' => '',
                    'database' => 0,
                    'prefix' => 'kode:jwt:',
                ],
                'memory' => [
                    'limit' => 10000,
                ],
                'file' => [
                    'path' => './storage/jwt',
                    'extension' => '.json',
                ],
                'database' => [
                    'dsn' => 'mysql:host=localhost;dbname=jwt',
                    'username' => 'root',
                    'password' => '',
                    'table' => 'jwt_tokens',
                    'options' => [],
                ],
                'apcu' => [
                    'prefix' => 'kode:jwt:',
                ],
                'memcached' => [
                    'servers' => [
                        ['host' => '127.0.0.1', 'port' => 11211],
                    ],
                    'prefix' => 'kode:jwt:',
                ],
                'coroutine_redis' => [
                    'host' => '127.0.0.1',
                    'port' => 6379,
                    'password' => '',
                    'database' => 0,
                    'prefix' => 'kode:jwt:',
                ],
            ],
            
            'events' => [
                'enabled' => true,
                'listeners' => [],
            ],
        ];
    }
    
    /**
     * 获取配置值
     */
    public function get(string $key, $default = null)
    {
        $keys = explode('.', $key);
        $config = $this->config;
        
        foreach ($keys as $segment) {
            if (!is_array($config) || !array_key_exists($segment, $config)) {
                return $default;
            }
            
            $config = $config[$segment];
        }
        
        return $config;
    }
    
    /**
     * 设置配置值
     */
    public function set(string $key, $value): void
    {
        $keys = explode('.', $key);
        $config = &$this->config;
        
        foreach ($keys as $segment) {
            if (!is_array($config)) {
                $config = [];
            }
            
            $config = &$config[$segment];
        }
        
        $config = $value;
    }
    
    /**
     * 获取所有配置
     */
    public function all(): array
    {
        return $this->config;
    }
    
    /**
     * 合并配置
     */
    public function merge(array $config): void
    {
        $this->config = array_merge_recursive($this->config, $config);
    }
}