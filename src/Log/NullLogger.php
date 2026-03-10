<?php

declare(strict_types=1);

namespace Kode\Jwt\Log;

use Kode\Jwt\Contract\LoggerInterface;

/**
 * 空日志实现
 *
 * 在未启用日志或不希望产生 I/O 开销时使用。
 * 所有日志调用都会被安全忽略，不影响主流程。
 */
class NullLogger implements LoggerInterface
{
    /**
     * 记录调试日志（空实现）
     *
     * @param string $message 日志消息
     * @param array<string, mixed> $context 上下文
     * @return void
     */
    public function debug(string $message, array $context = []): void
    {
    }

    /**
     * 记录信息日志（空实现）
     *
     * @param string $message 日志消息
     * @param array<string, mixed> $context 上下文
     * @return void
     */
    public function info(string $message, array $context = []): void
    {
    }

    /**
     * 记录警告日志（空实现）
     *
     * @param string $message 日志消息
     * @param array<string, mixed> $context 上下文
     * @return void
     */
    public function warning(string $message, array $context = []): void
    {
    }

    /**
     * 记录错误日志（空实现）
     *
     * @param string $message 日志消息
     * @param array<string, mixed> $context 上下文
     * @return void
     */
    public function error(string $message, array $context = []): void
    {
    }
}
