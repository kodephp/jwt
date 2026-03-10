<?php

declare(strict_types=1);

namespace Kode\Jwt\Contract;

/**
 * JWT 日志接口
 *
 * 定义包内统一日志能力，支持按级别记录结构化上下文，
 * 便于故障定位、安全审计和运行状态追踪。
 */
interface LoggerInterface
{
    /**
     * 记录调试级日志
     *
     * 适用于开发排查、行为追踪等低优先级场景。
     *
     * @param string $message 日志消息
     * @param array<string, mixed> $context 上下文数据
     * @return void
     */
    public function debug(string $message, array $context = []): void;

    /**
     * 记录信息级日志
     *
     * 适用于关键业务节点，如 Token 签发、刷新、注销等。
     *
     * @param string $message 日志消息
     * @param array<string, mixed> $context 上下文数据
     * @return void
     */
    public function info(string $message, array $context = []): void;

    /**
     * 记录警告级日志
     *
     * 适用于潜在风险场景，如配置缺失、异常输入等。
     *
     * @param string $message 日志消息
     * @param array<string, mixed> $context 上下文数据
     * @return void
     */
    public function warning(string $message, array $context = []): void;

    /**
     * 记录错误级日志
     *
     * 适用于业务失败、依赖异常、签名验证失败等错误场景。
     *
     * @param string $message 日志消息
     * @param array<string, mixed> $context 上下文数据
     * @return void
     */
    public function error(string $message, array $context = []): void;
}
