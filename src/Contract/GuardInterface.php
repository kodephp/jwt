<?php

namespace Kode\Jwt\Contract;

use Kode\Jwt\Token\Payload;

interface GuardInterface
{
    /**
     * 生成Token
     *
     * @param Payload $payload Payload实例
     * @return array<string, mixed>
     */
    public function issue(Payload $payload): array;

    /**
     * 验证Token
     *
     * @param string $token Token字符串
     * @return Payload 验证通过的Payload实例
     */
    public function authenticate(string $token): Payload;

    /**
     * 刷新Token
     *
     * @param string $token 旧Token字符串
     * @return array<string, mixed> 新的Token数组
     */
    public function refresh(string $token): array;

    /**
     * 使Token失效
     *
     * @param string $token
     * @return bool
     */
    public function invalidate(string $token): bool;

    /**
     * 检查是否唯一登录（用于SSO）
     *
     * @param string $uid
     * @param string $platform
     * @return bool
     */
    public function isUnique(string $uid, string $platform): bool;

    /**
     * 注册Token（用于SSO）
     *
     * @param string $uid
     * @param string $platform
     * @param string $jti
     * @return void
     */
    public function register(string $uid, string $platform, string $jti): void;
}
