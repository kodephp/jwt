<?php

namespace Kode\Jwt\Guard;

use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Parser;
use Kode\Jwt\Event\EventDispatcher;

class MloGuard extends BaseGuard
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
        // 多点登录不需要特殊处理
        // Token信息已经在BaseGuard中存储
    }
}