<?php

/**
 * 存储驱动使用示例
 * 展示如何使用不同的存储后端
 */

// 引入自动加载文件
require_once __DIR__ . '/../vendor/autoload.php';

use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

echo "=== Kode JWT 存储驱动使用示例 ===\n\n";

echo "--- 1. 内存存储 (Memory Storage) ---\n\n";

KodeJwt::init([
    'guards' => [
        'api' => [
            'driver' => 'sso',
            'storage' => 'memory',
            'blacklist_enabled' => true,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'ttl' => 1440,
            'algo' => 'HS256',
            'secret' => 'example_secret_key_for_memory',
        ],
    ],
    'storage' => [
        'memory' => [
            'limit' => 10000,
        ]
    ],
]);

$now = time();
$ttl = 1440;

$payload = Payload::create(
    uid: 1001,
    username: 'memory_user',
    platform: 'web',
    exp: $now + $ttl,
    iat: $now,
    jti: bin2hex(random_bytes(16)),
    roles: ['user'],
    perms: ['read']
);

$token = KodeJwt::issue($payload)['token'];
echo "使用内存存储生成的 Token: {$token}\n";

$verified = KodeJwt::authenticate($token);
echo "Token 验证成功，用户: {$verified->username}\n\n";

echo "--- 2. Redis 存储示例 (需要 ext-redis) ---\n\n";

try {
    KodeJwt::init([
        'guards' => [
            'api' => [
                'driver' => 'sso',
                'storage' => 'redis',
                'blacklist_enabled' => true,
                'refresh_enabled' => true,
                'refresh_ttl' => 20160,
                'ttl' => 1440,
                'algo' => 'HS256',
                'secret' => 'example_secret_key_for_redis',
            ],
        ],
        'storage' => [
            'redis' => [
                'host' => '127.0.0.1',
                'port' => 6379,
                'password' => '',
                'database' => 0,
                'prefix' => 'kode_jwt:',
                'timeout' => 2.0,
                'read_timeout' => 60.0,
            ]
        ],
    ]);

    $now = time();
    $ttl = 1440;

    $payload = Payload::create(
        uid: 1002,
        username: 'redis_user',
        platform: 'app',
        exp: $now + $ttl,
        iat: $now,
        jti: bin2hex(random_bytes(16)),
        roles: ['user', 'vip'],
        perms: ['read', 'write']
    );

    $token = KodeJwt::issue($payload)['token'];
    echo "使用 Redis 存储生成的 Token: {$token}\n";

    $verified = KodeJwt::authenticate($token);
    echo "Token 验证成功，用户: {$verified->username}\n";

    $tokenKey = "token:{$verified->jti}";
    echo "Token 在 Redis 中的键: {$tokenKey}\n\n";

} catch (Exception $e) {
    echo "Redis 连接失败: " . $e->getMessage() . "\n";
    echo "请确保 Redis 服务已启动并安装 ext-redis 扩展\n\n";
}

echo "--- 3. 文件存储示例 ---\n\n";

KodeJwt::init([
    'guards' => [
        'api' => [
            'driver' => 'sso',
            'storage' => 'file',
            'blacklist_enabled' => true,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'ttl' => 1440,
            'algo' => 'HS256',
            'secret' => 'example_secret_key_for_file',
        ],
    ],
    'storage' => [
        'file' => [
            'directory' => __DIR__ . '/runtime/jwt_storage',
            'prefix' => 'jwt_',
        ]
    ],
]);

$storageDir = __DIR__ . '/runtime/jwt_storage';
if (!is_dir($storageDir)) {
    mkdir($storageDir, 0755, true);
}

$now = time();
$ttl = 1440;

$payload = Payload::create(
    uid: 1003,
    username: 'file_user',
    platform: 'desktop',
    exp: $now + $ttl,
    iat: $now,
    jti: bin2hex(random_bytes(16)),
    roles: ['user', 'admin'],
    perms: ['read', 'write', 'delete']
);

$token = KodeJwt::issue($payload)['token'];
echo "使用文件存储生成的 Token: {$token}\n";

$verified = KodeJwt::authenticate($token);
echo "Token 验证成功，用户: {$verified->username}\n";

$tokenFile = $storageDir . '/token_' . md5($verified->jti) . '.json';
if (file_exists($tokenFile)) {
    $storedData = json_decode(file_get_contents($tokenFile), true);
    echo "Token 数据已保存到文件\n";
    echo "文件路径: {$tokenFile}\n";
}

echo "\n--- 4. 多存储切换示例 ---\n\n";

function getStorageConfig(string $type): array
{
    $configs = [
        'memory' => [
            'driver' => 'sso',
            'storage' => 'memory',
            'blacklist_enabled' => true,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'ttl' => 1440,
            'algo' => 'HS256',
            'secret' => 'shared_secret_key',
        ],
        'file' => [
            'driver' => 'sso',
            'storage' => 'file',
            'blacklist_enabled' => true,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'ttl' => 1440,
            'algo' => 'HS256',
            'secret' => 'shared_secret_key',
        ],
    ];

    $config = $configs[$type] ?? $configs['memory'];
    $config['storage'] = $type;

    if ($type === 'file') {
        $config['storage_config'] = [
            'directory' => __DIR__ . '/runtime/jwt_storage',
            'prefix' => 'jwt_',
        ];
    }

    return $config;
}

foreach (['memory', 'file'] as $storageType) {
    $config = getStorageConfig($storageType);
    KodeJwt::init([
        'guards' => [
            'api' => $config,
        ],
    ]);

    $now = time();
    $ttl = 1440;

    $payload = Payload::create(
        uid: 2000 + rand(1, 100),
        username: "{$storageType}_user_" . time(),
        platform: $storageType,
        exp: $now + $ttl,
        iat: $now,
        jti: bin2hex(random_bytes(16)),
        roles: ['user'],
        perms: ['read']
    );

    $token = KodeJwt::issue($payload)['token'];
    echo "使用 {$storageType} 存储生成的 Token: " . substr($token, 0, 50) . "...\n";
}

echo "\n=== 存储驱动使用示例执行完成 ===\n";
