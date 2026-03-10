<?php

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
            $key = "user:{$uid}:{$platform}:tokens";
            $tokenIds = $this->storage->get($key) ?? [];

            foreach ($tokenIds as $jti) {
                $tokenData = $this->storage->get("token:{$jti}");
                if ($tokenData && !$this->storage->isBlacklisted($jti)) {
                    $tokens[] = $tokenData;
                }
            }
        } else {
            // 获取所有平台的Token
            foreach ($this->config->get('platforms', []) as $plat) {
                $key = "user:{$uid}:{$plat}:tokens";
                $tokenIds = $this->storage->get($key) ?? [];

                foreach ($tokenIds as $jti) {
                    $tokenData = $this->storage->get("token:{$jti}");
                    if ($tokenData && !$this->storage->isBlacklisted($jti)) {
                        $tokens[] = $tokenData;
                    }
                }
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
        $revokedCount = 0;

        if ($platform) {
            // 注销指定平台的Token
            $key = "user:{$uid}:{$platform}:tokens";
            $tokenIds = $this->storage->get($key) ?? [];

            foreach ($tokenIds as $jti) {
                $tokenData = $this->storage->get("token:{$jti}");
                if (is_array($tokenData) && isset($tokenData['token']) && is_string($tokenData['token'])) {
                    $revoked = $this->guard->invalidate($tokenData['token']);
                } else {
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
        } else {
            // 注销所有平台的Token
            foreach ($this->config->get('platforms', []) as $plat) {
                $key = "user:{$uid}:{$plat}:tokens";
                $tokenIds = $this->storage->get($key) ?? [];

                foreach ($tokenIds as $jti) {
                    $tokenData = $this->storage->get("token:{$jti}");
                    if (is_array($tokenData) && isset($tokenData['token']) && is_string($tokenData['token'])) {
                        $revoked = $this->guard->invalidate($tokenData['token']);
                    } else {
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
        } catch (\Exception $e) {
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
     * @return int
     */
    public function cleanExpiredTokens(): int
    {
        $result = $this->storage->cleanExpired();
        return $result ? 1 : 0;
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
