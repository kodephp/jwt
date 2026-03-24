<?php

declare(strict_types=1);

/**
 * Kode JWT 存储驱动使用示例
 *
 * 展示如何使用不同的存储后端：内存、Redis、文件等
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;
use Kode\Jwt\Storage\MemoryStorage;
use Kode\Jwt\Enum\StorageType;

echo "=== Kode JWT 存储驱动使用示例 ===\n\n";

// 1. 内存存储
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
    jti: bin2hex(random_bytes(16)),
    roles: ['user'],
    perms: ['read']
);

$token = KodeJwt::issue($payload)['token'];
echo "Token 生成成功: " . substr($token, 0, 50) . "...\n";
$verified = KodeJwt::authenticate($token);
echo "验证成功，用户: {$verified->username}\n\n";

// 2. Redis 存储
echo "--- 2. Redis 存储 (需要 ext-redis) ---\n\n";
try {
    KodeJwt::init([
        'guards' => [
            'api' => [
                'driver' => 'sso',
                'storage' => 'redis',
                'secret' => 'redis-secret-key',
            ],
        ],
        'storage' => [
            'redis' => [
                'host' => '127.0.0.1',
                'port' => 6379,
                'password' => '',
                'database' => 0,
                'prefix' => 'kode_jwt:',
            ]
        ],
    ]);

    $payload = Payload::create(
        uid: 1002,
        username: 'redis_user',
        platform: 'app',
        exp: time() + 3600,
        iat: time(),
        jti: bin2hex(random_bytes(16)),
        roles: ['user', 'vip']
    );

    $token = KodeJwt::issue($payload)['token'];
    echo "Redis Token: " . substr($token, 0, 50) . "...\n";
    $verified = KodeJwt::authenticate($token);
    echo "验证成功，用户: {$verified->username}\n\n";
} catch (\Exception $e) {
    echo "Redis 连接失败: {$e->getMessage()}\n";
    echo "请确保 Redis 服务已启动并安装 ext-redis\n\n";
}

// 3. 文件存储
echo "--- 3. 文件存储 (File Storage) ---\n\n";
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
    jti: bin2hex(random_bytes(16)),
    roles: ['user', 'admin']
);

$token = KodeJwt::issue($payload)['token'];
echo "文件存储 Token: " . substr($token, 0, 50) . "...\n";
$verified = KodeJwt::authenticate($token);
echo "验证成功，用户: {$verified->username}\n\n";

// 4. 存储接口增强功能
echo "--- 4. 存储接口增强功能 ---\n\n";
$storage = new MemoryStorage(['limit' => 100]);

$storage->set('test_key', 'test_value', 3600);
echo "设置键值: test_key = test_value\n";

$remainingTtl = $storage->getRemainingTtl('test_key');
echo "剩余 TTL: {$remainingTtl} 秒\n";

$storage->touch('test_key', 7200);
echo "TTL 已延长到 7200 秒\n";

$stats = $storage->getStats();
echo "存储统计: storage_count={$stats['storage_count']}, limit={$stats['limit']}\n\n";

// 5. 存储类型枚举
echo "--- 5. 存储类型枚举 ---\n\n";
echo "Redis 是否持久化: " . (StorageType::REDIS->isPersistent() ? '是' : '否') . "\n";
echo "内存存储是否持久化: " . (StorageType::MEMORY->isPersistent() ? '是' : '否') . "\n";
echo "Redis 需要扩展: " . (StorageType::REDIS->requiresExtension() ?? '无') . "\n\n";

echo "=== 存储驱动示例执行完成 ===\n";
