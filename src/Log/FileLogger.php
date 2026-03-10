<?php

declare(strict_types=1);

namespace Kode\Jwt\Log;

use Kode\Jwt\Contract\LoggerInterface;

/**
 * 文件日志实现
 *
 * 采用 JSON 行格式记录日志，便于日志采集系统解析。
 * 适用于生产环境审计、问题追踪和安全分析。
 */
class FileLogger implements LoggerInterface
{
    private string $filePath;
    private string $minLevel;

    /**
     * 构造日志实例
     *
     * @param string $filePath 日志文件绝对路径或相对路径
     * @param string $minLevel 最低记录级别（debug/info/warning/error）
     */
    public function __construct(string $filePath, string $minLevel = 'info')
    {
        $this->filePath = $filePath;
        $this->minLevel = $this->normalizeLevel($minLevel);
    }

    /**
     * 记录调试级日志
     *
     * @param string $message 日志消息
     * @param array<string, mixed> $context 上下文数据
     * @return void
     */
    public function debug(string $message, array $context = []): void
    {
        $this->write('debug', $message, $context);
    }

    /**
     * 记录信息级日志
     *
     * @param string $message 日志消息
     * @param array<string, mixed> $context 上下文数据
     * @return void
     */
    public function info(string $message, array $context = []): void
    {
        $this->write('info', $message, $context);
    }

    /**
     * 记录警告级日志
     *
     * @param string $message 日志消息
     * @param array<string, mixed> $context 上下文数据
     * @return void
     */
    public function warning(string $message, array $context = []): void
    {
        $this->write('warning', $message, $context);
    }

    /**
     * 记录错误级日志
     *
     * @param string $message 日志消息
     * @param array<string, mixed> $context 上下文数据
     * @return void
     */
    public function error(string $message, array $context = []): void
    {
        $this->write('error', $message, $context);
    }

    /**
     * 输出日志到文件
     *
     * @param string $level 日志级别
     * @param string $message 日志消息
     * @param array<string, mixed> $context 上下文数据
     * @return void
     */
    private function write(string $level, string $message, array $context): void
    {
        if (!$this->shouldWrite($level)) {
            return;
        }

        $dir = dirname($this->filePath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0775, true);
        }

        $record = [
            'time' => date('c'),
            'level' => $level,
            'message' => $message,
            'context' => $context,
        ];

        $line = json_encode($record, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($line === false) {
            return;
        }

        @file_put_contents($this->filePath, $line . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    /**
     * 判断当前级别是否应当记录
     *
     * @param string $level 当前日志级别
     * @return bool
     */
    private function shouldWrite(string $level): bool
    {
        $weights = [
            'debug' => 100,
            'info' => 200,
            'warning' => 300,
            'error' => 400,
        ];

        return ($weights[$level] ?? 1000) >= ($weights[$this->minLevel] ?? 200);
    }

    /**
     * 规范化日志级别
     *
     * @param string $level 原始日志级别
     * @return string 规范化后的日志级别
     */
    private function normalizeLevel(string $level): string
    {
        $normalized = strtolower(trim($level));
        return in_array($normalized, ['debug', 'info', 'warning', 'error'], true) ? $normalized : 'info';
    }
}
