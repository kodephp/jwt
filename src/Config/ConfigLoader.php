<?php

declare(strict_types=1);

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
        $this->config = $this->mergeDistinct($this->getDefaultConfig(), $config);
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
            'logging' => [
                'enabled' => false,
                'driver' => 'file',
                'path' => './logs/kode-jwt.log',
                'level' => 'info',
            ],

            /**
             * 防重放保护配置
             *
             * 模式：
             *   - strict  : 严格模式，Nonce 一经使用立即拒绝二次出现
             *   - lenient : 宽松模式，结合滑动窗口限制异常高频
             *   - off     : 关闭防重放
             */
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
        $this->config = $this->mergeDistinct($this->config, $config);
    }

    /**
     * 递归合并配置（后者覆盖前者）
     *
     * 该方法用于避免 array_merge_recursive 将标量合并为数组，
     * 从而引发配置结构异常和类型不一致问题。
     *
     * @param array<string, mixed> $base 基础配置
     * @param array<string, mixed> $override 覆盖配置
     * @return array<string, mixed>
     */
    private function mergeDistinct(array $base, array $override): array
    {
        foreach ($override as $key => $value) {
            if (is_array($value) && isset($base[$key]) && is_array($base[$key])) {
                $base[$key] = $this->mergeDistinct($base[$key], $value);
                continue;
            }

            $base[$key] = $value;
        }

        return $base;
    }
}
