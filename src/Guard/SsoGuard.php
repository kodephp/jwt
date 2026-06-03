<?php

declare(strict_types=1);

namespace Kode\Jwt\Guard;

use Kode\Jwt\Contract\LoggerInterface;
use Kode\Jwt\Contract\SsoStorageInterface;
use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Event\EventDispatcher;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Parser;

class SsoGuard extends BaseGuard
{
    /**
     * SSO 守卫构造函数
     *
     * 该守卫用于实现"同一用户同一平台仅允许一个有效 Token"的策略。
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
     *
     * 优先使用 SsoStorageInterface 的 getSsoMapping / atomicRevoke；
     * 降级到通用 storage->get + blacklist。
     */
    public function isUnique(string $uid, string $platform): bool
    {
        $ssoKey = "sso:{$uid}:{$platform}";
        $existing = $this->storage instanceof SsoStorageInterface
            ? $this->storage->getSsoMapping($uid, $platform)
            : $this->storage->get($ssoKey);

        if (empty($existing)) {
            return true;
        }

        $jti = (string) $existing;
        if ($this->storage instanceof SsoStorageInterface) {
            $ttl = $this->getTtlSeconds() + $this->getRefreshTtlSeconds();
            $this->storage->atomicRevoke($jti, $uid, $platform, max(1, $ttl));
        } else {
            $this->storage->blacklist($jti);
            $this->storage->delete($ssoKey);
        }

        $this->logger->info('SSO 检测到历史会话，已自动踢出旧 Token', [
            'uid' => $uid,
            'platform' => $platform,
            'old_jti' => $jti,
        ]);
        return true;
    }

    /**
     * 注册 Token
     *
     * 优先使用 SsoStorageInterface 便捷方法；降级到通用 set。
     */
    public function register(string $uid, string $platform, string $jti): void
    {
        $ttl = max(1, $this->getTtlSeconds() + $this->getRefreshTtlSeconds());

        if ($this->storage instanceof SsoStorageInterface) {
            $this->storage->setSsoMapping($uid, $platform, $jti, $ttl);
            $this->storage->trackUserToken($uid, $platform, $jti, $ttl);
        } else {
            $this->storage->set("sso:{$uid}:{$platform}", $jti, $ttl);
        }

        $this->logger->debug('SSO 会话注册完成', ['uid' => $uid, 'platform' => $platform, 'jti' => $jti]);
    }

    /**
     * 获取当前 SSO 绑定 JTI（用于诊断与运维）
     */
    public function currentJti(string $uid, string $platform): ?string
    {
        if ($this->storage instanceof SsoStorageInterface) {
            return $this->storage->getSsoMapping($uid, $platform);
        }
        $value = $this->storage->get("sso:{$uid}:{$platform}");
        return $value !== null ? (string) $value : null;
    }
}
