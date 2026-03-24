<?php

declare(strict_types=1);

namespace Kode\Jwt\Log;

use Kode\Jwt\Contract\LoggerInterface;

/**
 * Monolog 日志适配器
 *
 * 将 Monolog Logger 适配为 JWT 包的 LoggerInterface
 */
final class MonologAdapter implements LoggerInterface
{
    private object $logger;

    public function __construct(object $logger)
    {
        $this->logger = $logger;
    }

    public function emergency(string $message, array $context = []): void
    {
        $this->logger->emergency($message, $context);
    }

    public function alert(string $message, array $context = []): void
    {
        $this->logger->alert($message, $context);
    }

    public function critical(string $message, array $context = []): void
    {
        $this->logger->critical($message, $context);
    }

    public function error(string $message, array $context = []): void
    {
        $this->logger->error($message, $context);
    }

    public function warning(string $message, array $context = []): void
    {
        $this->logger->warning($message, $context);
    }

    public function notice(string $message, array $context = []): void
    {
        $this->logger->notice($message, $context);
    }

    public function info(string $message, array $context = []): void
    {
        $this->logger->info($message, $context);
    }

    public function debug(string $message, array $context = []): void
    {
        $this->logger->debug($message, $context);
    }

    public function log(string $level, string $message, array $context = []): void
    {
        $this->logger->log($level, $message, $context);
    }

    /**
     * 获取底层 Monolog 实例
     */
    public function getMonolog(): object
    {
        return $this->logger;
    }
}
