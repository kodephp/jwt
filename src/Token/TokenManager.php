<?php

namespace Kode\Jwt\Token;

use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Contract\GuardInterface;
use Kode\Jwt\Config\ConfigLoader;
use Kode\Jwt\KodeJwt;

class TokenManager
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
     * 获取用户的所有活跃Token
     */
    public function getUserTokens(string $uid, string $platform = null): array
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
     */
    public function revokeUserTokens(string $uid, string $platform = null): int
    {
        $revokedCount = 0;
        
        if ($platform) {
            // 注销指定平台的Token
            $key = "user:{$uid}:{$platform}:tokens";
            $tokenIds = $this->storage->get($key) ?? [];
            
            foreach ($tokenIds as $jti) {
                if ($this->guard->invalidate($jti)) {
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
                    if ($this->guard->invalidate($jti)) {
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
     */
    public function cleanExpiredTokens(): int
    {
        return $this->storage->cleanExpired();
    }
    
    /**
     * 获取Token统计信息
     */
    public function getStats(): array
    {
        return $this->storage->getStats();
    }
}