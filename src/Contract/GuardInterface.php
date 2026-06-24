<?php

declare(strict_types=1);

namespace Kode\Jwt\Contract;

use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Exception\TokenBlacklistedException;
use Kode\Jwt\Exception\TokenExpiredException;
use Kode\Jwt\Exception\TokenInvalidException;
use Kode\Jwt\Exception\TokenReplayException;
use Kode\Jwt\Token\Payload;

interface GuardInterface
{
    /**
     * 生成Token
     *
     * @param Payload $payload Payload实例
     * @return array<string, mixed>
     * @throws JwtException 当Token生成或签名失败时抛出异常
     */
    public function issue(Payload $payload): array;

    /**
     * 验证Token
     *
     * @param string $token Token字符串
     * @return Payload 验证通过的Payload实例
     * @throws TokenInvalidException 当Token格式无效或签名错误时抛出异常
     * @throws TokenExpiredException 当Token已过期时抛出异常
     * @throws TokenBlacklistedException 当Token已被列入黑名单时抛出异常
     * @throws TokenReplayException 当检测到Token重放攻击时抛出异常
     */
    public function authenticate(string $token): Payload;

    /**
     * 刷新Token
     *
     * @param string $token 旧Token字符串
     * @return array<string, mixed> 新的Token数组
     * @throws TokenInvalidException 当旧Token无效时抛出异常
     * @throws TokenExpiredException 当旧Token已超出刷新期时抛出异常
     * @throws JwtException 当刷新功能未启用或刷新失败时抛出异常
     */
    public function refresh(string $token): array;

    /**
     * 使Token失效
     *
     * @param string $token
     * @return bool
     * @throws TokenInvalidException 当Token无效时抛出异常
     * @throws JwtException 当写入黑名单失败时抛出异常
     */
    public function invalidate(string $token): bool;

    /**
     * 检查是否唯一登录（用于SSO）
     *
     * @param string $uid
     * @param string $platform
     * @return bool
     * @throws JwtException 当存储读取失败时抛出异常
     */
    public function isUnique(string $uid, string $platform): bool;

    /**
     * 注册Token（用于SSO）
     *
     * @param string $uid
     * @param string $platform
     * @param string $jti
     * @return void
     * @throws JwtException 当存储写入失败时抛出异常
     */
    public function register(string $uid, string $platform, string $jti): void;
}
