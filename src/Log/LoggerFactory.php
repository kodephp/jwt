<?php

declare(strict_types=1);

namespace Kode\Jwt\Log;

use Kode\Jwt\Contract\LoggerInterface;

/**
 * 日志工厂
 *
 * 负责根据配置构建日志实例，屏蔽上层业务对底层实现的感知。
 */
class LoggerFactory
{
    /**
     * 创建日志实例
     *
     * 配置示例：
     * - ['enabled' => true, 'driver' => 'file', 'path' => '/tmp/jwt.log', 'level' => 'info']
     * - ['enabled' => false]
     *
     * @param array<string, mixed> $config 日志配置
     * @return LoggerInterface
     */
    public static function create(array $config): LoggerInterface
    {
        $enabled = (bool) ($config['enabled'] ?? false);
        if (!$enabled) {
            return new NullLogger();
        }

        $driver = strtolower((string) ($config['driver'] ?? 'file'));
        if ($driver !== 'file') {
            return new NullLogger();
        }

        $path = (string) ($config['path'] ?? './logs/kode-jwt.log');
        $level = (string) ($config['level'] ?? 'info');

        return new FileLogger($path, $level);
    }
}
