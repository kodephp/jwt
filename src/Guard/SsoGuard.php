<?php

namespace Kode\Jwt\Guard;

use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Parser;
use Kode\Jwt\Event\EventDispatcher;

class SsoGuard extends BaseGuard
{
    public function __construct(
        StorageInterface $storage,
        Builder $builder,
        Parser $parser,
        EventDispatcher $eventDispatcher,
        array $config = []
    ) {
        parent::__construct($storage, $builder, $parser, $eventDispatcher, $config);
    }
    
    /**
     * 检查是否唯一登录
     */
    public function isUnique(string $uid, string $platform): bool
    {
        // 对于SSO，检查是否已存在该用户的Token
        $key = "sso:{$uid}:{$platform}";
        $existing = $this->storage->get($key);
        
        if ($existing) {
            // 如果存在，将旧Token加入黑名单
            $this->storage->blacklist($existing);
            $this->storage->delete($key);
        }
        
        return true;
    }
    
    /**
     * 注册Token
     */
    public function register(string $uid, string $platform, string $jti): void
    {
        $key = "sso:{$uid}:{$platform}";
        $ttl = $this->config['ttl'] ?? 3600;
        
        // 存储当前Token的JTI
        $this->storage->set($key, $jti, $ttl);
    }
}