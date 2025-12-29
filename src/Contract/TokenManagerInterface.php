<?php

namespace Kode\Jwt\Contract;

use Kode\Jwt\Token\Payload;

interface TokenManagerInterface
{
    /**
     * 生成Token
     */
    public function issue(Payload $payload): array;

    /**
     * 验证Token
     */
    public function authenticate(string $token): Payload;

    /**
     * 刷新Token
     */
    public function refresh(string $token): array;

    /**
     * 注销Token
     */
    public function invalidate(string $token): bool;

    /**
     * 检查Token是否唯一（用于SSO）
     */
    public function isUnique(string $uid, string $platform): bool;

    /**
     * 注册Token
     */
    public function register(string $uid, string $platform, string $jti): void;

    /**
     * 获取存储实例
     */
    public function getStorage(): StorageInterface;

    /**
     * 获取配置
     */
    public function getConfig(): array;
}
