<?php

namespace Kode\Jwt\Config;

class ConfigLoader
{
    /**
     * @var array<string, mixed>
     */
    private array $config;

    /**
     * 构造函数
     *
     * @param array<string, mixed> $config 配置数组
     */
    public function __construct(array $config = [])
    {
        $this->config = array_merge($this->getDefaultConfig(), $config);
    }

    /**
     * 获取默认配置
     *
     * @return array<string, mixed>
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
     *
     * @param string $key 配置键（支持点号分隔的嵌套键）
     * @param mixed $default 默认值
     * @return mixed
     */
    public function get(string $key, mixed $default = null): mixed
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
     *
     * @param string $key 配置键（支持点号分隔的嵌套键）
     * @param mixed $value 要设置的值
     */
    public function set(string $key, mixed $value): void
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
     *
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->config;
    }

    /**
     * 合并配置
     *
     * @param array<string, mixed> $config 要合并的配置数组
     */
    public function merge(array $config): void
    {
        $this->config = array_merge_recursive($this->config, $config);
    }
}
