<?php

declare(strict_types=1);

namespace Kode\Jwt\Metrics;

/**
 * Prometheus 监控指标收集器
 *
 * 提供 Token 数量、刷新频率等监控指标
 */
class PrometheusMetrics
{
    /**
     * @var array<string, int|float> 计数器指标
     */
    protected array $counters = [];

    /**
     * @var array<string, array{value: int|float, labels: array<string, string>}> 直方图指标
     */
    protected array $histograms = [];

    /**
     * @var array<string, int|float> 仪表盘指标
     */
    protected array $gauges = [];

    /**
     * @var string 指标命名空间
     */
    protected string $namespace;

    public function __construct(string $namespace = 'kode_jwt')
    {
        $this->namespace = $namespace;
        $this->initDefaultMetrics();
    }

    /**
     * 初始化默认指标
     */
    protected function initDefaultMetrics(): void
    {
        $this->counters = [
            'tokens_issued_total' => 0,
            'tokens_authenticated_total' => 0,
            'tokens_refreshed_total' => 0,
            'tokens_invalidated_total' => 0,
            'tokens_blacklisted_total' => 0,
            'authentication_failures_total' => 0,
            'token_expired_total' => 0,
            'token_invalid_total' => 0,
        ];

        $this->gauges = [
            'active_tokens' => 0,
            'blacklisted_tokens' => 0,
            'storage_keys_count' => 0,
        ];
    }

    /**
     * 记录 Token 签发
     */
    public function recordTokenIssued(string $guard = 'api', string $platform = 'default'): void
    {
        $this->incrementCounter('tokens_issued_total', ['guard' => $guard, 'platform' => $platform]);
    }

    /**
     * 记录 Token 认证成功
     */
    public function recordTokenAuthenticated(string $guard = 'api'): void
    {
        $this->incrementCounter('tokens_authenticated_total', ['guard' => $guard]);
    }

    /**
     * 记录 Token 刷新
     */
    public function recordTokenRefreshed(string $guard = 'api'): void
    {
        $this->incrementCounter('tokens_refreshed_total', ['guard' => $guard]);
    }

    /**
     * 记录 Token 注销
     */
    public function recordTokenInvalidated(string $guard = 'api'): void
    {
        $this->incrementCounter('tokens_invalidated_total', ['guard' => $guard]);
    }

    /**
     * 记录 Token 加入黑名单
     */
    public function recordTokenBlacklisted(string $guard = 'api'): void
    {
        $this->incrementCounter('tokens_blacklisted_total', ['guard' => $guard]);
    }

    /**
     * 记录认证失败
     */
    public function recordAuthenticationFailure(string $reason = 'unknown', string $guard = 'api'): void
    {
        $this->incrementCounter('authentication_failures_total', ['reason' => $reason, 'guard' => $guard]);
    }

    /**
     * 记录 Token 过期
     */
    public function recordTokenExpired(string $guard = 'api'): void
    {
        $this->incrementCounter('token_expired_total', ['guard' => $guard]);
    }

    /**
     * 记录 Token 无效
     */
    public function recordTokenInvalid(string $guard = 'api'): void
    {
        $this->incrementCounter('token_invalid_total', ['guard' => $guard]);
    }

    /**
     * 更新活跃 Token 数量
     */
    public function setActiveTokens(int $count, string $guard = 'api'): void
    {
        $this->setGauge('active_tokens', $count, ['guard' => $guard]);
    }

    /**
     * 更新黑名单 Token 数量
     */
    public function setBlacklistedTokens(int $count, string $guard = 'api'): void
    {
        $this->setGauge('blacklisted_tokens', $count, ['guard' => $guard]);
    }

    /**
     * 更新存储键数量
     */
    public function setStorageKeysCount(int $count, string $storage = 'memory'): void
    {
        $this->setGauge('storage_keys_count', $count, ['storage' => $storage]);
    }

    /**
     * 记录操作耗时
     */
    public function recordOperationDuration(string $operation, float $seconds, array $labels = []): void
    {
        $key = 'operation_duration_seconds';
        if (!isset($this->histograms[$key])) {
            $this->histograms[$key] = [];
        }

        $this->histograms[$key][] = [
            'value' => $seconds,
            'labels' => array_merge(['operation' => $operation], $labels),
        ];
    }

    /**
     * 增加计数器
     */
    protected function incrementCounter(string $name, array $labels = []): void
    {
        $key = $this->buildMetricKey($name, $labels);
        $this->counters[$key] = ($this->counters[$key] ?? 0) + 1;
    }

    /**
     * 设置仪表盘值
     */
    protected function setGauge(string $name, int|float $value, array $labels = []): void
    {
        $key = $this->buildMetricKey($name, $labels);
        $this->gauges[$key] = $value;
    }

    /**
     * 构建指标键
     */
    protected function buildMetricKey(string $name, array $labels = []): string
    {
        if (empty($labels)) {
            return $name;
        }

        ksort($labels);
        $labelStr = implode(',', array_map(
            fn($k, $v) => "{$k}=\"{$v}\"",
            array_keys($labels),
            array_values($labels)
        ));

        return "{$name}{{$labelStr}}";
    }

    /**
     * 导出 Prometheus 格式指标
     */
    public function export(): string
    {
        $output = [];

        // 导出计数器
        foreach ($this->counters as $key => $value) {
            $name = explode('{', $key)[0];
            $output[] = "# HELP {$this->namespace}_{$name} Total count of {$name}";
            $output[] = "# TYPE {$this->namespace}_{$name} counter";
            $output[] = "{$this->namespace}_{$key} {$value}";
        }

        // 导出仪表盘
        foreach ($this->gauges as $key => $value) {
            $name = explode('{', $key)[0];
            $output[] = "# HELP {$this->namespace}_{$name} Current value of {$name}";
            $output[] = "# TYPE {$this->namespace}_{$name} gauge";
            $output[] = "{$this->namespace}_{$key} {$value}";
        }

        // 导出直方图
        foreach ($this->histograms as $name => $data) {
            $output[] = "# HELP {$this->namespace}_{$name} Duration of operations in seconds";
            $output[] = "# TYPE {$this->namespace}_{$name} histogram";

            foreach ($data as $item) {
                $labels = $item['labels'];
                $labelStr = implode(',', array_map(
                    fn(string $k, string $v) => "{$k}=\"{$v}\"",
                    array_keys((array)$labels),
                    array_values((array)$labels)
                ));
                $output[] = "{$this->namespace}_{$name}{{$labelStr}} {$item['value']}";
            }
        }

        return implode("\n", $output) . "\n";
    }

    /**
     * 获取所有指标数组
     */
    public function toArray(): array
    {
        return [
            'counters' => $this->counters,
            'gauges' => $this->gauges,
            'histograms' => $this->histograms,
        ];
    }

    /**
     * 重置所有指标
     */
    public function reset(): void
    {
        $this->initDefaultMetrics();
        $this->histograms = [];
    }

    /**
     * 计时辅助方法
     */
    public function timeOperation(string $operation, callable $callback, array $labels = []): mixed
    {
        $start = microtime(true);
        $result = $callback();
        $duration = microtime(true) - $start;

        $this->recordOperationDuration($operation, $duration, $labels);

        return $result;
    }
}
