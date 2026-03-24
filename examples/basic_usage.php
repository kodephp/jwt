<?php

declare(strict_types=1);

/**
 * Kode JWT 基础使用示例
 *
 * 展示 JWT Token 的生成、验证、刷新、注销等核心功能
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

echo "=== Kode JWT 基础使用示例 ===\n\n";

// 1. 初始化配置
echo "1. 初始化配置...\n";
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
            'secret' => 'your-secret-key-here',
        ],
    ],
    'storage' => [
        'memory' => ['limit' => 10000],
    ],
    'logging' => [
        'enabled' => false,
    ],
]);
echo "配置初始化完成\n\n";

// 2. 创建 Payload 并生成 Token
echo "2. 创建 Payload 并生成 Token...\n";
$now = time();
$payload = Payload::create(
    uid: 1001,
    username: 'john_doe',
    platform: 'web',
    exp: $now + 3600,
    iat: $now,
    jti: bin2hex(random_bytes(16)),
    roles: ['user', 'admin'],
    perms: ['read', 'write', 'delete']
);

$result = KodeJwt::issue($payload);
$token = $result['token'];
echo "Token 生成成功\n";
echo "过期时间: {$result['expires_in']} 秒\n\n";

// 3. 验证 Token
echo "3. 验证 Token...\n";
$verified = KodeJwt::authenticate($token);
echo "验证成功\n";
echo "用户 ID: {$verified->uid}\n";
echo "用户名: {$verified->username}\n";
echo "角色: " . implode(', ', $verified->roles ?? []) . "\n\n";

// 4. 刷新 Token
echo "4. 刷新 Token...\n";
$refreshed = KodeJwt::refresh($token);
echo "Token 刷新成功\n";
echo "新 Token: " . substr($refreshed['token'], 0, 50) . "...\n\n";

// 5. 注销 Token
echo "5. 注销原始 Token...\n";
KodeJwt::invalidate($token);
echo "Token 已注销\n\n";

// 6. 验证已注销的 Token
echo "6. 验证已注销的 Token...\n";
try {
    KodeJwt::authenticate($token);
    echo "错误: 已注销的 Token 不应该有效\n";
} catch (\Kode\Jwt\Exception\TokenBlacklistedException $e) {
    echo "正确: 已注销的 Token 被拒绝\n";
    echo "异常信息: {$e->getMessage()}\n\n";
}

// 7. 使用刷新后的 Token
echo "7. 使用刷新后的 Token...\n";
$verifiedNew = KodeJwt::authenticate($refreshed['token']);
echo "刷新后的 Token 仍然有效\n";
echo "用户 ID: {$verifiedNew->uid}\n\n";

echo "=== 基础示例执行完成 ===\n";
