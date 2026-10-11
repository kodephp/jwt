<?php

declare(strict_types=1);

namespace Kode\Jwt\Token;

use Kode\Jwt\Contract\TokenManagerInterface;
use Kode\Jwt\Contract\GuardInterface;
use Kode\Jwt\Config\ConfigLoader;
use Kode\Jwt\Contract\StorageInterface;

class TokenManager implements TokenManagerInterface
{
    private StorageInterface $storage;
    private GuardInterface $guard;
    private ConfigLoader $config;

    public function __construct(
        StorageInterface $storage,
        GuardInterface $guard,
        ConfigLoader $config
    ) {
        $this->storage = $storage;
        $this->guard = $guard;
        $this->config = $config;
    }

    /**
     * 生成Token
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function issue(Payload $payload): array
    {
        return $this->guard->issue($payload);
    }

    /**
     * 验证Token
     */
    #[\Override]
    public function authenticate(string $token): Payload
    {
        return $this->guard->authenticate($token);
    }

    /**
     * 刷新Token
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function refresh(string $token): array
    {
        return $this->guard->refresh($token);
    }

    /**
     * 注销Token
     */
    #[\Override]
    public function invalidate(string $token): bool
    {
        return $this->guard->invalidate($token);
    }

    /**
     * 检查Token是否唯一（用于SSO）
     */
    #[\Override]
    public function isUnique(string $uid, string $platform): bool
    {
        return $this->guard->isUnique($uid, $platform);
    }

    /**
     * 注册Token
     */
    #[\Override]
    public function register(string $uid, string $platform, string $jti): void
    {
        $this->guard->register($uid, $platform, $jti);
    }

    /**
     * 获取存储实例
     */
    #[\Override]
    public function getStorage(): StorageInterface
    {
        return $this->storage;
    }

    /**
     * 获取配置
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function getConfig(): array
    {
        return $this->config->all();
    }

    /**
     * 获取用户的所有活跃Token
     *
     * @return array<int, array<string, mixed>>
     */
    public function getUserTokens(string $uid, ?string $platform = null): array
    {
        $tokens = [];

        if ($platform) {
            // 获取指定平台的Token
            $tokens = $this->collectPlatformTokens($uid, $platform);
        } else {
            // 获取所有平台的Token
            foreach ($this->config->get('platforms', []) as $plat) {
                $tokens = array_merge($tokens, $this->collectPlatformTokens($uid, $plat));
            }
        }

        return $tokens;
    }

    /**
     * 收集指定平台下的活跃Token列表
     *
     * 使用 getMultiple 批量获取Token详情，避免逐个查询造成的N+1问题。
     *
     * @param string $uid 用户ID
     * @param string $platform 平台标识
     * @return array<int, array<string, mixed>>
     */
    private function collectPlatformTokens(string $uid, string $platform): array
    {
        $key = "user:{$uid}:{$platform}:tokens";
        $tokenIds = $this->storage->get($key) ?? [];

        if (empty($tokenIds)) {
            return [];
        }

        // 批量构建Token详情键
        $tokenKeys = array_map(fn($jti) => "token:{$jti}", $tokenIds);

        // 批量获取Token详情，避免N+1查询
        $tokenDataMap = $this->storage->getMultiple($tokenKeys);

        $tokens = [];
        foreach ($tokenIds as $jti) {
            $tokenData = $tokenDataMap["token:{$jti}"] ?? null;
            // 过滤黑名单中的Token
            if ($tokenData && !$this->storage->isBlacklisted($jti)) {
                $tokens[] = $tokenData;
            }
        }

        return $tokens;
    }

    /**
     * 获取用户在指定平台的活跃Token数量
     *
     * @param string $uid 用户ID
     * @param string $platform 平台标识
     * @return int 活跃Token数量
     */
    public function getUserTokenCount(string $uid, string $platform): int
    {
        $key = "user:{$uid}:{$platform}:tokens";
        $tokenIds = $this->storage->get($key) ?? [];

        $validCount = 0;
        foreach ($tokenIds as $jti) {
            if (!$this->storage->isBlacklisted($jti)) {
                $validCount++;
            }
        }

        return $validCount;
    }

    /**
     * 获取用户在所有平台的活跃Token数量
     *
     * @param string $uid 用户ID
     * @return int 总活跃Token数量
     */
    public function getUserTotalTokenCount(string $uid): int
    {
        $totalCount = 0;

        foreach ($this->config->get('platforms', []) as $platform) {
            $totalCount += $this->getUserTokenCount($uid, $platform);
        }

        return $totalCount;
    }

    /**
     * 强制注销用户的所有Token
     *
     * 往返预算是这一枚方法的契约：它是账号处置的唯一下线口（禁用账号、禁用/删除角色、
     * 会话页那颗「清理过期会话」都调它），而调用方是在一个批次里逐账号问的。
     * 旧写法对每个平台各发一次 `get()`、再把清单里每枚 jti 各问一次详情，
     * 于是「一次点击」= 账号数 ×（平台数 + 令牌数）次串行往返 —— 结果全对、一个错都不报，
     * 慢的那部分只体现在 worker 被按住多久上（回归见 tests/RevokeBatchReadTest.php）。
     * 现在清单一次批量读、详情一次批量读、清单一次批量删。
     *
     * @param string $uid 用户ID
     * @param string|null $platform 平台标识（可选）
     * @return int 被注销的Token数量
     */
    public function revokeUserTokens(string $uid, ?string $platform = null): int
    {
        $platforms = ($platform === null || $platform === '')
            ? array_values(array_filter(
                (array) $this->config->get('platforms', []),
                static fn(mixed $p): bool => is_string($p) && $p !== ''
            ))
            : [$platform];

        if ($platforms === []) {
            return 0;
        }

        $listKeys = [];
        foreach ($platforms as $plat) {
            $listKeys[] = "user:{$uid}:{$plat}:tokens";
        }

        $lists = $this->storage->getMultiple($listKeys, []);

        $detailKeys = [];
        foreach ($listKeys as $key) {
            foreach ((array) ($lists[$key] ?? []) as $jti) {
                if (is_string($jti) && $jti !== '') {
                    $detailKeys["token:{$jti}"] = true;
                }
            }
        }

        $details = $detailKeys === []
            ? []
            : $this->storage->getMultiple(array_keys($detailKeys), []);

        $revokedCount = 0;
        foreach ($listKeys as $key) {
            $revokedCount += $this->revokeList((array) ($lists[$key] ?? []), $details);
        }

        // 清单一次批量删（逐平台 delete() 又是要省掉的那一圈往返）
        $this->storage->deleteMultiple($listKeys);

        return $revokedCount;
    }

    /**
     * 注销一枚清单里的所有 Token。
     *
     * 详情由调用方一次批量读好后传进来（理由见 revokeUserTokens 的往返预算）。
     * 优先通过 guard->invalidate() 注销完整Token，无法获取原始Token时
     * 退化为按 jti 加入黑名单 —— 缺详情不等于没撤销，那一枚必须照样进黑名单。
     *
     * @param array<mixed> $tokenIds
     * @param array<string, mixed> $details 以 token:{jti} 为键
     * @return int 被注销的Token数量
     */
    private function revokeList(array $tokenIds, array $details): int
    {
        $revokedCount = 0;
        foreach ($tokenIds as $jti) {
            if (!is_string($jti) || $jti === '') {
                continue;
            }

            $tokenData = $details["token:{$jti}"] ?? null;
            if (is_array($tokenData) && isset($tokenData['token']) && is_string($tokenData['token'])) {
                // 优先通过完整Token执行注销流程
                $revoked = $this->guard->invalidate($tokenData['token']);
            } else {
                // 无法获取原始Token时，按过期时间计算黑名单TTL
                $ttl = is_array($tokenData) && isset($tokenData['exp'])
                    ? max(1, (int) $tokenData['exp'] - time())
                    : 3600;
                $revoked = $this->storage->blacklist($jti, $ttl);
            }

            if ($revoked) {
                $revokedCount++;
            }
        }

        return $revokedCount;
    }

    /**
     * 检查Token是否有效
     *
     * @param string $token JWT Token
     * @return bool 是否有效
     */
    public function isTokenValid(string $token): bool
    {
        try {
            $payload = $this->guard->authenticate($token);
            return !$this->storage->isBlacklisted($payload->jti);
        } catch (\Kode\Jwt\Exception\JwtException $e) {
            // 仅捕获JWT相关异常，避免吞掉其他系统级错误
            return false;
        }
    }

    /**
     * 获取Token信息
     *
     * @return array<string, mixed>|null
     */
    public function getTokenInfo(string $token): ?array
    {
        try {
            $payload = $this->guard->authenticate($token);
            return $this->storage->get("token:{$payload->jti}");
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * 批量清理过期Token
     *
     * @return int 清理的Token数量
     */
    public function cleanExpiredTokens(): int
    {
        $result = $this->storage->cleanExpired();
        // 兼容存储驱动返回 bool 或 int 两种情况，保留实际清理数量
        return is_int($result) ? $result : ($result ? 1 : 0);
    }

    /**
     * 获取Token统计信息
     *
     * @return array<string, mixed>
     */
    public function getStats(): array
    {
        return $this->storage->getStats();
    }
}
