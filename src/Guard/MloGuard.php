<?php

declare(strict_types=1);

namespace Kode\Jwt\Guard;

use Kode\Jwt\Contract\LoggerInterface;
use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Event\EventDispatcher;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Parser;

class MloGuard extends BaseGuard
{
    /**
     * MLO 守卫构造函数
     *
     * MLO（多点登录）模式允许同一用户在同一平台保留多个活跃会话，
     * 适合多设备并发登录场景。
     *
     * @param StorageInterface $storage 存储驱动实例
     * @param Builder $builder Token 构建器
     * @param Parser $parser Token 解析器
     * @param EventDispatcher $eventDispatcher 事件分发器
     * @param LoggerInterface|null $logger 日志实例
     * @param array<string, mixed> $config 守卫配置
     */
    public function __construct(
        StorageInterface $storage,
        Builder $builder,
        Parser $parser,
        EventDispatcher $eventDispatcher,
        ?LoggerInterface $logger = null,
        array $config = []
    ) {
        parent::__construct($storage, $builder, $parser, $eventDispatcher, $logger, $config);
    }

    /**
     * 检查Token是否唯一（多点登录总是返回true）
     */
    public function isUnique(string $uid, string $platform): bool
    {
        // 多点登录不需要检查唯一性
        return true;
    }

    /**
     * 注册Token（多点登录不需要特殊处理）
     */
    public function register(string $uid, string $platform, string $jti): void
    {
        $this->logger->debug('MLO 会话注册完成', ['uid' => $uid, 'platform' => $platform, 'jti' => $jti]);
    }
}
