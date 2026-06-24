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
    public function issue(Payload $payload): array
    {
        return $this->guard->issue($payload);
    }

    /**
     * 验证Token
     */
    public function authenticate(string $token): Payload
    {
        return $this->guard->authenticate($token);
    }

    /**
     * 刷新Token
     *
     * @return array<string, mixed>
     */
    public function refresh(string $token): array
    {
        return $this->guard->refresh($token);
    }

    /**
     * 注销Token
     */
    public function invalidate(string $token): bool
    {
        return $this->guard->invalidate($token);
    }

    /**
     * 检查Token是否唯一（用于SSO）
     */
    public function isUnique(string $uid, string $platform): bool
    {
        return $this->guard->isUnique($uid, $platform);
    }

    /**
     * 注册Token
     */
    public function register(string $uid, string $platform, string $jti): void
    {
        $this->guard->register($uid, $platform, $jti);
    }

    /**
     * 获取存储实例
     */
    public function getStorage(): StorageInterface
    {
        return $this->storage;
    }

    /**
     * 获取配置
     *
     * @return array<string, mixed>
     */
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
     * @param string $uid 用户ID
     * @param string|null $platform 平台标识（可选）
     * @return int 被注销的Token数量
     */
    public function revokeUserTokens(string $uid, ?string $platform = null): int
    {
        if ($platform) {
            // 注销指定平台的Token
            return $this->revokeTokensFromList($uid, $platform);
        }

        // 注销所有平台的Token
        $revokedCount = 0;
        foreach ($this->config->get('platforms', []) as $plat) {
            $revokedCount += $this->revokeTokensFromList($uid, $plat);
        }

        return $revokedCount;
    }

    /**
     * 注销指定用户在指定平台下的所有Token
     *
     * 抽取自 revokeUserTokens()，统一处理单个平台的Token注销逻辑：
     * 优先通过 guard->invalidate() 注销完整Token，无法获取原始Token时
     * 退化为按 jti 加入黑名单。
     *
     * @param string $uid 用户ID
     * @param string $platform 平台标识
     * @return int 被注销的Token数量
     */
    private function revokeTokensFromList(string $uid, string $platform): int
    {
        $key = "user:{$uid}:{$platform}:tokens";
        $tokenIds = $this->storage->get($key) ?? [];

        $revokedCount = 0;
        foreach ($tokenIds as $jti) {
            $tokenData = $this->storage->get("token:{$jti}");
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

        // 清空Token列表
        $this->storage->delete($key);

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
