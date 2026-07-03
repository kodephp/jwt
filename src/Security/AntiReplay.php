<?php

declare(strict_types=1);

namespace Kode\Jwt\Security;

use Kode\Jwt\Contract\ReplayProtectionInterface;
use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Storage\RedisReplayProtection;
use Kode\Jwt\Storage\StorageFactory;

/**
 * 防重放（Anti-Replay）管理器
 *
 * 提供开箱即用的防重放保护能力，主要职责：
 * 1. 根据配置与运行环境自动选择最合适的实现（Redis/降级/关闭）。
 * 2. 提供 Nonce 生成、首次消费、滑动窗口等能力。
 * 3. 与 Guard / Builder / Parser 协同，贯穿签发→验证→刷新全链路。
 *
 * 工作模式：
 *   - strict  : 严格模式，任何 JTI+Nonce 二次出现都视为重放。
 *   - lenient : 宽松模式，仅在滑动窗口内多次出现才视为异常。
 *   - off     : 关闭防重放。
 */
class AntiReplay
{
    public const MODE_STRICT  = 'strict';
    public const MODE_LENIENT = 'lenient';
    public const MODE_OFF     = 'off';

    private ?ReplayProtectionInterface $backend = null;
    private string $mode = self::MODE_OFF;
    private bool $requireNonce = false;
    private int $windowSeconds = 0;
    private int $maxRequests = 0;

    /**
     * 构造函数
     *
     * @param array<string, mixed> $config 配置数组
     *   - mode                : strict|lenient|off
     *   - require_nonce       : bool 是否强制要求 Nonce 字段
     *   - window              : int  滑动窗口大小（秒）
     *   - max_requests        : int  滑动窗口内最大允许次数
     *   - backend             : string  使用的后端，默认 'redis'
     *   - redis_storage       : string  关联的 Redis 存储名称
     */
    public function __construct(array $config = [])
    {
        $this->mode = strtolower((string) ($config['mode'] ?? self::MODE_OFF));
        $this->requireNonce = (bool) ($config['require_nonce'] ?? false);
        $this->windowSeconds = (int) ($config['window'] ?? 0);
        $this->maxRequests = (int) ($config['max_requests'] ?? 0);
    }

    /**
     * 绑定后端实现
     */
    public function withBackend(ReplayProtectionInterface $backend): self
    {
        $this->backend = $backend;
        return $this;
    }

    /**
     * 通过 KodeJwt 配置自动初始化后端
     *
     * @param array<string, mixed> $jwtConfig 完整 JWT 配置
     */
    public function bootstrapFromConfig(array $jwtConfig): bool
    {
        if ($this->mode === self::MODE_OFF) {
            $this->backend = null;
            return false;
        }

        $replayConfig = $jwtConfig['replay'] ?? [];
        $backendName = strtolower((string) ($replayConfig['backend'] ?? 'redis'));

        if ($backendName !== 'redis') {
            return false;
        }

        // 解析 Redis 存储
        $storageName = (string) ($replayConfig['redis_storage'] ?? 'redis');
        $factory = new StorageFactory(
            new \Kode\Jwt\Config\ConfigLoader($jwtConfig)
        );

        try {
            $storage = $factory->create($storageName);
        } catch (\Throwable $e) {
            return false;
        }

        if (!method_exists($storage, 'getRedis')) {
            return false;
        }

        $this->backend = new RedisReplayProtection(
            $storage,
            [
                'prefix'              => $replayConfig['prefix'] ?? 'kode:jwt:',
                'ttl'                 => (int) ($replayConfig['ttl'] ?? 3600),
                'sliding_window'      => (int) ($replayConfig['window'] ?? $this->windowSeconds),
                'sliding_max_requests' => (int) ($replayConfig['max_requests'] ?? $this->maxRequests),
            ]
        );

        return true;
    }

    /**
     * 生成一次性 Nonce
     *
     * @param int $length Nonce 字节长度
     * @throws \RuntimeException 当 CSPRNG 不可用时抛出
     */
    public static function generateNonce(int $length = 16): string
    {
        if ($length < 1) {
            $length = 16;
        }

        try {
            return bin2hex(random_bytes($length));
        } catch (\Throwable $e) {
            throw new \RuntimeException('CSPRNG is not available: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 检查并消费 Nonce
     *
     * @param string $jti   JWT ID
     * @param string|null $nonce Nonce 值
     * @param int $ttl 记录保留时间（秒）
     * @return bool true=通过；false=重放或缺失必要信息
     */
    public function check(string $jti, ?string $nonce, int $ttl = 3600): bool
    {
        if ($this->mode === self::MODE_OFF || $this->backend === null) {
            return true;
        }

        if ($this->requireNonce && ($nonce === null || $nonce === '')) {
            return false;
        }

        if ($nonce === null || $nonce === '') {
            return true;
        }

        return $this->backend->checkAndStore($jti, $nonce, $ttl, $this->windowSeconds);
    }

    /**
     * 查询 Nonce 是否已被使用
     */
    public function seen(string $jti, ?string $nonce): bool
    {
        if ($this->backend === null) {
            return false;
        }
        if ($jti === '' || $nonce === null || $nonce === '') {
            return false;
        }
        return $this->backend->exists($jti, $nonce);
    }

    /**
     * 获取当前模式
     */
    public function getMode(): string
    {
        return $this->mode;
    }

    /**
     * 是否强制要求 Nonce
     */
    public function isRequireNonce(): bool
    {
        return $this->requireNonce;
    }

    /**
     * 是否启用
     */
    public function isEnabled(): bool
    {
        return $this->mode !== self::MODE_OFF && $this->backend !== null;
    }
}
