<?php

declare(strict_types=1);

namespace Kode\Jwt\KeyRotation;

use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Exception\JwtException;

/**
 * 密钥轮换管理器
 *
 * 支持密钥平滑过渡，旧密钥在过渡期内仍可用于验证，新密钥用于签名。
 */
class KeyRotationManager
{
    /**
     * 存储键前缀
     */
    protected const STORAGE_PREFIX = 'key_rotation:';

    /**
     * @var array<string, KeyVersion> 密钥版本缓存
     */
    protected array $keyCache = [];

    /**
     * @var int 密钥默认有效期（秒），默认 30 天
     */
    protected int $defaultKeyLifetime;

    /**
     * @var int 过渡期时长（秒），默认 7 天
     */
    protected int $transitionPeriod;

    public function __construct(
        protected StorageInterface $storage,
        protected string $keyType = 'hmac',
        int $defaultKeyLifetime = 2592000,
        int $transitionPeriod = 604800
    ) {
        $this->defaultKeyLifetime = $defaultKeyLifetime;
        $this->transitionPeriod = $transitionPeriod;
    }

    /**
     * 生成新的主密钥
     */
    public function generateNewKey(string $keyId = ''): KeyVersion
    {
        if ($keyId === '') {
            $keyId = 'key_' . bin2hex(random_bytes(8));
        }

        $key = $this->generateKeyMaterial();
        $now = time();

        // 将当前主密钥降级为次要密钥
        $currentPrimary = $this->getPrimaryKey();
        if ($currentPrimary !== null) {
            $this->demoteKey($currentPrimary->keyId);
        }

        $newKey = new KeyVersion(
            keyId: $keyId,
            key: $key,
            createdAt: $now,
            expiresAt: $now + $this->defaultKeyLifetime,
            isActive: true,
            isPrimary: true
        );

        $this->storeKeyVersion($newKey);
        $this->keyCache[$keyId] = $newKey;

        return $newKey;
    }

    /**
     * 获取当前主密钥
     */
    public function getPrimaryKey(): ?KeyVersion
    {
        $keys = $this->getAllKeys();

        foreach ($keys as $key) {
            if ($key->isPrimary && $key->isUsable()) {
                return $key;
            }
        }

        return null;
    }

    /**
     * 获取所有有效密钥
     *
     * @return array<string, KeyVersion>
     */
    public function getValidKeys(): array
    {
        $keys = $this->getAllKeys();
        $validKeys = [];

        foreach ($keys as $keyId => $key) {
            if ($key->isUsable()) {
                $validKeys[$keyId] = $key;
            }
        }

        return $validKeys;
    }

    /**
     * 根据 KeyId 获取密钥
     */
    public function getKeyById(string $keyId): ?KeyVersion
    {
        if (isset($this->keyCache[$keyId])) {
            return $this->keyCache[$keyId];
        }

        $keyData = $this->storage->get($this->getStorageKey($keyId));
        if ($keyData === null) {
            return null;
        }

        $key = KeyVersion::fromArray($keyData);
        $this->keyCache[$keyId] = $key;

        return $key;
    }

    /**
     * 获取用于签名的密钥（当前主密钥）
     */
    public function getSigningKey(): ?KeyVersion
    {
        return $this->getPrimaryKey();
    }

    /**
     * 获取用于验证的密钥列表（主密钥 + 过渡期内的旧密钥）
     *
     * @return array<string, KeyVersion>
     */
    public function getVerificationKeys(): array
    {
        $keys = $this->getValidKeys();
        $verificationKeys = [];
        $now = time();

        foreach ($keys as $keyId => $key) {
            // 主密钥始终可用于验证
            if ($key->isPrimary) {
                $verificationKeys[$keyId] = $key;
                continue;
            }

            // 过渡期内的旧密钥可用于验证
            $transitionEnd = $key->expiresAt + $this->transitionPeriod;
            if ($now < $transitionEnd) {
                $verificationKeys[$keyId] = $key;
            }
        }

        return $verificationKeys;
    }

    /**
     * 撤销指定密钥
     */
    public function revokeKey(string $keyId): bool
    {
        $key = $this->getKeyById($keyId);
        if ($key === null) {
            return false;
        }

        $revokedKey = new KeyVersion(
            keyId: $key->keyId,
            key: $key->key,
            createdAt: $key->createdAt,
            expiresAt: $key->expiresAt,
            isActive: false,
            isPrimary: false
        );

        $this->storeKeyVersion($revokedKey);
        unset($this->keyCache[$keyId]);

        return true;
    }

    /**
     * 清理过期密钥
     */
    public function cleanupExpiredKeys(): int
    {
        $keys = $this->getAllKeys();
        $cleanedCount = 0;
        $now = time();

        foreach ($keys as $keyId => $key) {
            // 过渡期结束后删除
            $transitionEnd = $key->expiresAt + $this->transitionPeriod;
            if ($now > $transitionEnd) {
                $this->storage->delete($this->getStorageKey($keyId));
                unset($this->keyCache[$keyId]);
                $cleanedCount++;
            }
        }

        return $cleanedCount;
    }

    /**
     * 获取密钥轮换状态
     */
    public function getRotationStatus(): array
    {
        $keys = $this->getAllKeys();
        $primary = $this->getPrimaryKey();
        $validKeys = $this->getValidKeys();
        $verificationKeys = $this->getVerificationKeys();

        return [
            'total_keys' => count($keys),
            'valid_keys' => count($validKeys),
            'verification_keys' => count($verificationKeys),
            'has_primary' => $primary !== null,
            'primary_key_id' => $primary?->keyId,
            'primary_expires_at' => $primary?->expiresAt,
            'primary_remaining_ttl' => $primary?->getRemainingTtl(),
            'transition_period' => $this->transitionPeriod,
            'default_lifetime' => $this->defaultKeyLifetime,
        ];
    }

    /**
     * 执行自动轮换（当主密钥即将过期时）
     */
    public function autoRotate(int $rotateBefore = 86400): ?KeyVersion
    {
        $primary = $this->getPrimaryKey();

        if ($primary === null) {
            return $this->generateNewKey();
        }

        // 主密钥将在指定时间内过期，触发轮换
        if ($primary->getRemainingTtl() < $rotateBefore) {
            return $this->generateNewKey();
        }

        return null;
    }

    /**
     * 获取所有密钥
     *
     * 优先使用 getMultiple 批量查询，避免 N+1 网络往返。
     *
     * @return array<string, KeyVersion>
     */
    protected function getAllKeys(): array
    {
        // 从存储中获取所有密钥 ID 列表
        $keyListKey = self::STORAGE_PREFIX . 'key_list';
        $keyIds = $this->storage->get($keyListKey, []);

        if (!is_array($keyIds) || empty($keyIds)) {
            return [];
        }

        // 区分已缓存与需批量查询的 keyId
        $cached = [];
        $uncached = [];
        foreach ($keyIds as $keyId) {
            $keyId = (string) $keyId;
            if (isset($this->keyCache[$keyId])) {
                $cached[$keyId] = $this->keyCache[$keyId];
            } else {
                $uncached[] = $keyId;
            }
        }

        // 对未缓存的 keyId 批量查询存储
        $fetched = [];
        if (!empty($uncached)) {
            $storageKeys = array_map(fn(string $id): string => $this->getStorageKey($id), $uncached);
            $rows = $this->storage->getMultiple($storageKeys, null);

            foreach ($uncached as $keyId) {
                $storageKey = $this->getStorageKey($keyId);
                $keyData = $rows[$storageKey] ?? null;
                if (is_array($keyData)) {
                    $key = KeyVersion::fromArray($keyData);
                    $this->keyCache[$keyId] = $key;
                    $fetched[$keyId] = $key;
                }
            }
        }

        return array_merge($cached, $fetched);
    }

    /**
     * 存储密钥版本
     */
    protected function storeKeyVersion(KeyVersion $keyVersion): void
    {
        $storageKey = $this->getStorageKey($keyVersion->keyId);
        $this->storage->set($storageKey, $keyVersion->toArray(), $this->defaultKeyLifetime + $this->transitionPeriod);

        // 更新密钥 ID 列表
        $keyListKey = self::STORAGE_PREFIX . 'key_list';
        $keyIds = $this->storage->get($keyListKey, []);

        if (!in_array($keyVersion->keyId, $keyIds, true)) {
            $keyIds[] = $keyVersion->keyId;
            $this->storage->set($keyListKey, $keyIds, $this->defaultKeyLifetime + $this->transitionPeriod);
        }
    }

    /**
     * 降级密钥（从主密钥变为次要密钥）
     */
    protected function demoteKey(string $keyId): void
    {
        $key = $this->getKeyById($keyId);
        if ($key === null) {
            return;
        }

        $demotedKey = new KeyVersion(
            keyId: $key->keyId,
            key: $key->key,
            createdAt: $key->createdAt,
            expiresAt: $key->expiresAt,
            isActive: $key->isActive,
            isPrimary: false
        );

        $this->storeKeyVersion($demotedKey);
        $this->keyCache[$keyId] = $demotedKey;
    }

    /**
     * 生成密钥材料
     */
    protected function generateKeyMaterial(): string
    {
        return match ($this->keyType) {
            'hmac' => bin2hex(random_bytes(32)),
            'rsa' => $this->generateRsaKeyPair(),
            'ecdsa' => $this->generateEcdsaKeyPair(),
            default => bin2hex(random_bytes(32)),
        };
    }

    /**
     * 生成 RSA 密钥对
     */
    protected function generateRsaKeyPair(): string
    {
        $config = [
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        $keyPair = openssl_pkey_new($config);
        if ($keyPair === false) {
            throw new JwtException('Failed to generate RSA key pair');
        }

        openssl_pkey_export($keyPair, $privateKey);

        return $privateKey;
    }

    /**
     * 生成 ECDSA 密钥对
     */
    protected function generateEcdsaKeyPair(): string
    {
        $config = [
            'digest_alg' => 'sha256',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ];

        $keyPair = openssl_pkey_new($config);
        if ($keyPair === false) {
            throw new JwtException('Failed to generate ECDSA key pair');
        }

        openssl_pkey_export($keyPair, $privateKey);

        return $privateKey;
    }

    /**
     * 获取存储键
     */
    protected function getStorageKey(string $keyId): string
    {
        return self::STORAGE_PREFIX . 'keys:' . $keyId;
    }
}
