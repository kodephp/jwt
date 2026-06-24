<?php

declare(strict_types=1);

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
     *
     * 根据存储驱动名称实例化对应的存储实现。对于 Redis 驱动，
     * 会自动检测是否运行在 Swoole 协程环境中，以选择协程安全的实现。
     *
     * @param string $name 存储驱动名称
     * @return StorageInterface
     * @throws \InvalidArgumentException 当配置缺失或驱动不支持时抛出
     */
    public function create(string $name): StorageInterface
    {
        $storageConfig = $this->config->get("storage.{$name}", []);

        if (empty($storageConfig)) {
            throw new \InvalidArgumentException("Storage '{$name}' not found in configuration");
        }

        switch ($name) {
            case 'memory':
                return new MemoryStorage($storageConfig);

            case 'redis':
                // 检查是否在Swoole协程环境中：需先确认扩展已加载，再判断协程上下文
                if (extension_loaded('swoole') && class_exists('Swoole\Coroutine') && \Swoole\Coroutine::getCid() > 0) {
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
                // 支持自定义存储：当驱动名为已存在的类名时直接实例化
                if (class_exists($name)) {
                    /** @var StorageInterface $instance */
                    $instance = new $name($storageConfig);
                    return $instance;
                }

                throw new \InvalidArgumentException("Unsupported storage driver: {$name}");
        }
    }
}
