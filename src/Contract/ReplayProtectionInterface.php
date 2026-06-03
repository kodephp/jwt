<?php

declare(strict_types=1);

namespace Kode\Jwt\Contract;

/**
 * 防重放保护接口
 *
 * 防重放（Anti-Replay）保护用于防止攻击者截获合法的 JWT 并在有效期内重复使用。
 * 典型实现基于一次性 Nonce、滑动窗口或服务端会话校验。
 *
 * 实现要点：
 * 1. Nonce 应当是 JTI 之外的独立值，攻击者无法预测或修改。
 * 2. 服务端记录最近一次或最近 N 次使用记录，超出窗口的非允许直接拒绝。
 * 3. 配合 Clock Skew 容忍与时间窗口边界，平衡安全与可用性。
 */
interface ReplayProtectionInterface
{
    /**
     * 检查并记录 Nonce（一次性消费语义）
     *
     * 返回 true 表示 Nonce 首次使用，可放行；
     * 返回 false 表示 Nonce 已存在（可能是重放），应当拒绝。
     *
     * @param string $jti     JWT ID
     * @param string $nonce   一次性随机值
     * @param int    $ttl     记录保留时间（秒），建议与 Token 过期时间一致
     * @param int    $window  时间窗口大小（秒），用于滑动窗口校验
     * @return bool 是否通过校验
     */
    public function checkAndStore(string $jti, string $nonce, int $ttl, int $window = 0): bool;

    /**
     * 检查 Nonce 是否已被消费（不写入新记录）
     *
     * @param string $jti   JWT ID
     * @param string $nonce 一次性随机值
     * @return bool 是否已被使用
     */
    public function exists(string $jti, string $nonce): bool;

    /**
     * 清理过期 Nonce（可选，部分实现可不提供）
     *
     * @return int 清理数量
     */
    public function purge(): int;
}
