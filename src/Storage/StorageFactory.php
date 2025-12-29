<?php

namespace Kode\Jwt\Storage;

use Kode\Jwt\Config\ConfigLoader;
use Kode\Jwt\Contract\StorageInterface;

class StorageFactory
{
    private ConfigLoader $config;

    public function __construct(ConfigLoader $config)
    {
        $this->config = $config;
    }

    /**
     * 创建存储实例
     */
    public function create(string $name): StorageInterface
    {
        $storageConfig = $this->config->get("storage.{$name}", []);

        if (empty($storageConfig)) {
            throw new \Exception("Storage '{$name}' not found in configuration");
        }

        switch ($name) {
            case 'memory':
                return new MemoryStorage($storageConfig);

            case 'redis':
                // 检查是否在Swoole环境中
                if (class_exists('Swoole\Coroutine') && \Swoole\Coroutine::getCid() > 0) {
                    return new CoroutineRedisStorage($storageConfig);
                }
                return new RedisStorage($storageConfig);

            case 'coroutine_redis':
                return new CoroutineRedisStorage($storageConfig);

            case 'database':
                return new DatabaseStorage($storageConfig);

            case 'file':
                return new FileStorage($storageConfig);

            case 'apcu':
                return new ApcuStorage($storageConfig);

            case 'memcached':
                return new MemcachedStorage($storageConfig);

            case 'null':
                return new NullStorage();

            default:
                // 支持自定义存储
                if (class_exists($name)) {
                    return new $name($storageConfig);
                }

                throw new \Exception("Unsupported storage driver: {$name}");
        }
    }
}
