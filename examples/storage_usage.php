<?php

declare(strict_types=1);

/**
 * Kode JWT 存储驱动使用示例（v1.8.x）
 *
 * 演示：
 * 1. 多种存储驱动（Memory / Redis / File）的使用
 * 2. SsoStorageInterface 增强能力（setSsoMapping / getSsoMapping / atomicRevoke）
 * 3. 用户活跃 Token 列表（trackUserToken / getUserActiveTokens）
 * 4. Token 详情与黑名单操作
 * 5. 存储统计与 TTL 维护
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;
use Kode\Jwt\Storage\MemoryStorage;
use Kode\Jwt\Contract\SsoStorageInterface;
use Kode\Jwt\Enum\StorageType;

echo "=== Kode JWT 存储驱动示例（v1.8.x） ===\n\n";

// 1. 内存存储（基础能力）
echo "--- 1. 内存存储 (Memory Storage) ---\n\n";
KodeJwt::init([
    'guards' => [
        'api' => [
            'driver' => 'sso',
            'storage' => 'memory',
            'blacklist_enabled' => true,
            'refresh_enabled' => true,
            'secret' => 'memory-secret-key',
        ],
    ],
    'storage' => [
        'memory' => ['limit' => 10000],
    ],
]);

$now = time();
$payload = Payload::create(
    uid: 1001,
    username: 'memory_user',
    platform: 'web',
    exp: $now + 3600,
    iat: $now,
    jti: Payload::generateJti(),
    roles: ['user'],
    perms: ['read']
);

$token = KodeJwt::issue($payload)['token'];
echo "Token 生成成功: " . substr($token, 0, 50) . "...\n";
$verified = KodeJwt::authenticate($token);
echo "验证成功，用户: {$verified->username}\n\n";

// 2. SsoStorageInterface 增强能力
echo "--- 2. SsoStorageInterface 增强能力 ---\n\n";
/** @var SsoStorageInterface $storage */
$storage = new MemoryStorage(['limit' => 1000]);

// 2.1 设置 / 读取 SSO 平台 → JTI 映射
$storage->setSsoMapping('1001', 'web', $verified->jti, 7200);
$boundJti = $storage->getSsoMapping('1001', 'web');
echo "SSO 绑定 JTI: {$boundJti}\n";

// 2.2 记录用户活跃 Token 列表
$storage->trackUserToken('1001', 'web', $verified->jti, 7200);
$tokens = $storage->get('user:1001:web:tokens', []);
echo "用户活跃 Token 数量: " . count((array) $tokens) . "\n";

// 2.3 原子化撤销（黑名单 + SSO 清理 + Token 列表清理 + 详情清理）
$affected = $storage->atomicRevoke($verified->jti, '1001', 'web', 3600);
echo "原子化撤销影响键数量: {$affected}\n";
echo "撤销后 SSO 绑定: " . var_export($storage->getSsoMapping('1001', 'web'), true) . "\n\n";

// 3. Redis 存储（如已安装 ext-redis）
echo "--- 3. Redis 存储 (需要 ext-redis) ---\n\n";
if (extension_loaded('redis')) {
    try {
        KodeJwt::init([
            'guards' => [
                'api' => [
                    'driver' => 'sso',
                    'storage' => 'redis',
                    'secret' => 'redis-secret-key',
                    'clock_skew' => 30,
                    'expected_claims' => [
                        'iss' => 'https://auth.example.com',
                    ],
                ],
            ],
            'storage' => [
                'redis' => [
                    'host' => '127.0.0.1',
                    'port' => 6379,
                    'password' => '',
                    'database' => 0,
                    'prefix' => 'kode_jwt:',
                    'persistent' => true,
                ]
            ],
            'replay' => [
                'mode' => 'strict',
                'require_nonce' => true,
                'window' => 60,
                'max_requests' => 5,
                'backend' => 'redis',
                'redis_storage' => 'redis',
            ],
        ]);

        $payload = Payload::create(
            uid: 1002,
            username: 'redis_user',
            platform: 'app',
            exp: time() + 3600,
            iat: time(),
            jti: Payload::generateJti(),
            roles: ['user', 'vip'],
            nonce: bin2hex(random_bytes(16)),
            audience: ['api.example.com'],
            issuer: 'https://auth.example.com',
        );

        $token = KodeJwt::issue($payload)['token'];
        echo "Redis Token: " . substr($token, 0, 50) . "...\n";
        $verified = KodeJwt::authenticate($token);
        echo "验证成功，用户: {$verified->username}\n";

        // 演示二次使用触发防重放
        try {
            KodeJwt::authenticate($token);
            echo "错误: 二次使用应当被拒绝（Nonce 已消费）\n";
        } catch (\Kode\Jwt\Exception\TokenReplayException $e) {
            echo "正确: 二次使用触发重放检测 — {$e->getMessage()}\n";
        }
        echo "\n";
    } catch (\Exception $e) {
        echo "Redis 连接失败: {$e->getMessage()}\n";
        echo "请确保 Redis 服务已启动并安装 ext-redis\n\n";
    }
} else {
    echo "未安装 ext-redis 扩展，跳过 Redis 演示。\n\n";
}

// 4. 文件存储
echo "--- 4. 文件存储 (File Storage) ---\n\n";
$storageDir = __DIR__ . '/runtime/jwt_storage';
if (!is_dir($storageDir)) {
    mkdir($storageDir, 0755, true);
}

KodeJwt::init([
    'guards' => [
        'api' => [
            'driver' => 'sso',
            'storage' => 'file',
            'secret' => 'file-secret-key',
        ],
    ],
    'storage' => [
        'file' => [
            'directory' => $storageDir,
            'prefix' => 'jwt_',
        ]
    ],
]);

$payload = Payload::create(
    uid: 1003,
    username: 'file_user',
    platform: 'desktop',
    exp: time() + 3600,
    iat: time(),
    jti: Payload::generateJti(),
    roles: ['user', 'admin']
);

$token = KodeJwt::issue($payload)['token'];
echo "文件存储 Token: " . substr($token, 0, 50) . "...\n";
$verified = KodeJwt::authenticate($token);
echo "验证成功，用户: {$verified->username}\n\n";

// 5. 存储接口增强功能
echo "--- 5. 存储接口增强功能 ---\n\n";
/** @var SsoStorageInterface $storage */
$storage = new MemoryStorage(['limit' => 100]);

$storage->set('test_key', 'test_value', 3600);
echo "设置键值: test_key = test_value\n";

$remainingTtl = $storage->getRemainingTtl('test_key');
echo "剩余 TTL: {$remainingTtl} 秒\n";

$storage->touch('test_key', 7200);
echo "TTL 已延长到 7200 秒\n";

$stats = $storage->getStats();
echo "存储统计: storage_count={$stats['storage_count']}, limit={$stats['limit']}\n\n";

// 6. 存储类型枚举
echo "--- 6. 存储类型枚举 ---\n\n";
echo "Redis 是否持久化: " . (StorageType::REDIS->isPersistent() ? '是' : '否') . "\n";
echo "内存存储是否持久化: " . (StorageType::MEMORY->isPersistent() ? '是' : '否') . "\n";
echo "Redis 需要扩展: " . (StorageType::REDIS->requiresExtension() ?? '无') . "\n\n";

echo "=== 存储驱动示例执行完成 ===\n";
