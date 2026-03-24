<?php

declare(strict_types=1);

namespace Kode\Jwt\Log;

use Kode\Jwt\Contract\LoggerInterface;

/**
 * 日志工厂
 *
 * 负责根据配置构建日志实例，支持多种日志驱动：
 * - null: 空日志（默认）
 * - file: 文件日志
 * - monolog: Monolog 日志（推荐，更健壮）
 */
class LoggerFactory
{
    /**
     * 创建日志实例
     *
     * 配置示例：
     * - ['enabled' => false]
     * - ['enabled' => true, 'driver' => 'file', 'path' => '/tmp/jwt.log', 'level' => 'info']
     * - ['enabled' => true, 'driver' => 'monolog', 'name' => 'jwt', 'handlers' => [...]]
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

        $driver = strtolower((string) ($config['driver'] ?? 'null'));

        return match ($driver) {
            'file' => self::createFileLogger($config),
            'monolog' => self::createMonologLogger($config),
            default => new NullLogger(),
        };
    }

    /**
     * 创建文件日志实例
     *
     * @param array<string, mixed> $config
     */
    private static function createFileLogger(array $config): LoggerInterface
    {
        $path = (string) ($config['path'] ?? './logs/kode-jwt.log');
        $level = (string) ($config['level'] ?? 'info');

        return new FileLogger($path, $level);
    }

    /**
     * 创建 Monolog 日志实例
     *
     * @param array<string, mixed> $config
     */
    private static function createMonologLogger(array $config): LoggerInterface
    {
        if (!class_exists(\Monolog\Logger::class)) {
            return new NullLogger();
        }

        $name = (string) ($config['name'] ?? 'kode-jwt');
        $handlers = $config['handlers'] ?? null;
        $processors = $config['processors'] ?? [];

        if ($handlers === null) {
            $path = (string) ($config['path'] ?? './logs/kode-jwt.log');
            $level = self::parseMonologLevel((string) ($config['level'] ?? 'info'));

            $handlers = [
                new \Monolog\Handler\StreamHandler($path, $level),
            ];
        }

        $monolog = new \Monolog\Logger($name, $handlers, $processors);

        return new MonologAdapter($monolog);
    }

    /**
     * 解析 Monolog 日志级别
     */
    private static function parseMonologLevel(string $level): int
    {
        $levelClass = \Monolog\Logger::class;

        return match (strtolower($level)) {
            'debug' => $levelClass::DEBUG,
            'info' => $levelClass::INFO,
            'notice' => $levelClass::NOTICE,
            'warning' => $levelClass::WARNING,
            'error' => $levelClass::ERROR,
            'critical' => $levelClass::CRITICAL,
            'alert' => $levelClass::ALERT,
            'emergency' => $levelClass::EMERGENCY,
            default => $levelClass::INFO,
        };
    }
}
