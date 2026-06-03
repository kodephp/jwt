<?php

declare(strict_types=1);

namespace Kode\Jwt\Contract;

/**
 * SSO 存储能力接口（可选）
 *
 * 实现该接口的存储后端可获得：
 * 1. 原子化撤销 Token（黑名单 + SSO 映射 + 用户 Token 列表 + Token 详情）
 * 2. 用户活跃 Token 列表维护
 * 3. SSO 平台 → JTI 映射便捷方法
 *
 * 业务层使用：
 * ```php
 * if ($storage instanceof SsoStorageInterface) {
 *     $storage->atomicRevoke($jti, $uid, $platform, $ttl);
 * } else {
 *     // 兼容实现：依次执行
 *     $storage->blacklist($jti, $ttl);
 *     $storage->delete("sso:{$uid}:{$platform}");
 *     $storage->delete("token:{$jti}");
 * }
 * ```
 *
 * 适用存储：
 * - RedisStorage、CoroutineRedisStorage（生产环境推荐，Lua 脚本保证原子性）
 * - MemoryStorage、FileStorage（单机场景，PHP-FPM 进程互斥可保证单进程原子性）
 * - 不适用：ApcuStorage、MemcachedStorage（共享内存/网络缓存，不保证原子性）
 */
interface SsoStorageInterface extends StorageInterface
{
    /**
     * 原子化撤销 Token
     *
     * 一次性完成以下四步：
     *   1. 将 JTI 加入黑名单
     *   2. 如果 SSO 映射匹配则清理 SSO 标记
     *   3. 从用户活跃 Token 列表中移除 JTI
     *   4. 删除 Token 详情键
     *
     * 推荐在 SSO 场景下使用，避免多步操作之间的并发漏洞。
     *
     * @param string $jti      JWT ID
     * @param string $uid      用户 ID
     * @param string $platform 平台标识
     * @param int    $ttl      黑名单保留时间（秒）
     * @return int 受影响键数量
     */
    public function atomicRevoke(string $jti, string $uid, string $platform, int $ttl = 3600): int;

    /**
     * 记录到用户活跃 Token 列表
     *
     * 列表默认仅保留最近 50 条以避免无限增长。
     *
     * @param string $uid      用户 ID
     * @param string $platform 平台标识
     * @param string $jti      JWT ID
     * @param int    $ttl      列表保留时间（秒）
     * @return bool
     */
    public function trackUserToken(string $uid, string $platform, string $jti, int $ttl = 0): bool;

    /**
     * 设置 SSO 平台 → JTI 映射
     */
    public function setSsoMapping(string $uid, string $platform, string $jti, int $ttl = 0): bool;

    /**
     * 获取 SSO 平台 → JTI 映射
     */
    public function getSsoMapping(string $uid, string $platform): ?string;
}
