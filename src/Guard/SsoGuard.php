<?php

declare(strict_types=1);

namespace Kode\Jwt\Guard;

use Kode\Jwt\Contract\LoggerInterface;
use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Event\EventDispatcher;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Parser;

class SsoGuard extends BaseGuard
{
    /**
     * SSO 守卫构造函数
     *
     * 该守卫用于实现“同一用户同一平台仅允许一个有效 Token”的策略。
     * 当用户重复登录时会自动使旧 Token 失效，确保账号状态唯一。
     *
     * @param StorageInterface $storage 存储驱动实例
     * @param Builder $builder Token 构建器
     * @param Parser $parser Token 解析器
     * @param EventDispatcher $eventDispatcher 事件分发器
     * @param LoggerInterface|null $logger 日志实例，未传入时使用空日志
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
     * 检查是否唯一登录
     */
    public function isUnique(string $uid, string $platform): bool
    {
        $key = "sso:{$uid}:{$platform}";
        $existing = $this->storage->get($key);

        if ($existing) {
            $this->storage->blacklist($existing);
            $this->storage->delete($key);
            $this->logger->info('SSO 检测到历史会话，已自动踢出旧 Token', [
                'uid' => $uid,
                'platform' => $platform,
                'old_jti' => $existing,
            ]);
        }

        return true;
    }

    /**
     * 注册Token
     */
    public function register(string $uid, string $platform, string $jti): void
    {
        $key = "sso:{$uid}:{$platform}";
        $ttl = $this->getTtlSeconds();

        $this->storage->set($key, $jti, $ttl);
        $this->logger->debug('SSO 会话注册完成', ['uid' => $uid, 'platform' => $platform, 'jti' => $jti]);
    }
}
