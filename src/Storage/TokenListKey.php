<?php

declare(strict_types=1);

namespace Kode\Jwt\Storage;

/**
 * 「这一枚键是不是用户活跃令牌清单」的唯一判据。
 *
 * 存在的理由是这个形状有两处不对称：
 * - `trackUserToken()` 用 LPUSH 把它写成**原生 LIST**（为了原子性和 50 条封顶）；
 * - 而读取方走的是通用 `StorageInterface::get()`，各驱动把 get/set 当同一个值，天然同型。
 *
 * 只有 redis 系驱动会分叉：GET/MGET 打在 LIST 键上都是 WRONGTYPE，phpredis 既不告警
 * 也不抛异常，直接回 false（实测 PHP 8.3 + phpredis 6：GET => false，TYPE => 3）。
 * 于是「按 uid 撤销该用户全部令牌」在 redis 驱动上恒查 0 条：强制下线点了没反应，
 * 接口还回 200 —— 这是 v1.14.1 修掉的那一刀。
 *
 * 所以读侧有两个入口（`get()` 与 `getMultiple()`），它们必须认同一份判据。
 * 判据写在驱动里过一次、再在批量读那一圈抄第二遍，就是下一次分叉的开始。
 */
final class TokenListKey
{
    /** 用户活跃 Token 列表键的后缀（trackUserToken 写、TokenManager/BaseGuard 读） */
    public const SUFFIX = ':tokens';

    /**
     * 只判后缀：前缀加在键名**前面**，不影响这一判据。
     */
    public static function isListKey(string $key): bool
    {
        return str_ends_with($key, self::SUFFIX);
    }
}
