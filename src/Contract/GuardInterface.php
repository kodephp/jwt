<?php

namespace Kode\Jwt\Contract;

use Kode\Jwt\Token\Payload;

interface GuardInterface
{
    /**
     * 生成Token
     *
     * @param Payload $payload
     * @return array
     */
    public function issue(Payload $payload): array;

    /**
     * 验证Token
     *
     * @param string $token
     * @return Payload
     */
    public function authenticate(string $token): Payload;

    /**
     * 刷新Token
     *
     * @param string $token
     * @return array
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