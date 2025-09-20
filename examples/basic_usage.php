<?php

/**
 * Kode JWT 包使用示例
 */

// 引入自动加载文件
require_once __DIR__ . '/../vendor/autoload.php';

use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

// 设置配置
KodeJwt::setConfig([
    'guards' => [
        'api' => [
            'driver' => 'sso',
            'storage' => 'memory',
            'blacklist_enabled' => true,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'ttl' => 1440,
            'algo' => 'HS256',
            'secret' => 'example_secret_key',
        ],
    ],
    'storage' => [
        'memory' => [
            'limit' => 10000,
        ]
    ],
]);

try {
    echo "=== Kode JWT 使用示例 ===\n\n";

    // 1. 创建 Payload
    echo "1. 创建 Payload...\n";
    $payload = new Payload(
        uid: 123,
        username: 'john_doe',
        platform: 'app',
        exp: time() + 3600, // 1小时后过期
        iat: time(),
        jti: uniqid('jwt_', true),
        roles: ['user', 'admin'],
        perms: ['read', 'write', 'delete'],
        custom: ['department' => 'IT', 'level' => 5]
    );
    
    echo "Payload 创建成功\n\n";

    // 2. 生成 Token
    echo "2. 生成 Token...\n";
    $result = KodeJwt::issue($payload);
    $token = $result['token'];
    
    echo "Token 生成成功:\n";
    echo "Token: {$token}\n";
    echo "Expires in: {$result['expires_in']} seconds\n";
    echo "Refresh TTL: {$result['refresh_ttl']} seconds\n\n";

    // 3. 验证 Token
    echo "3. 验证 Token...\n";
    $verifiedPayload = KodeJwt::authenticate($token);
    
    echo "Token 验证成功:\n";
    echo "User ID: {$verifiedPayload->uid}\n";
    echo "Username: {$verifiedPayload->username}\n";
    echo "Platform: {$verifiedPayload->platform}\n";
    echo "Roles: " . implode(', ', $verifiedPayload->roles) . "\n";
    echo "Permissions: " . implode(', ', $verifiedPayload->perms) . "\n";
    echo "Custom data: " . json_encode($verifiedPayload->custom) . "\n\n";

    // 4. 刷新 Token
    echo "4. 刷新 Token...\n";
    $refreshResult = KodeJwt::refresh($token);
    $newToken = $refreshResult['token'];
    
    echo "Token 刷新成功:\n";
    echo "New Token: {$newToken}\n";
    echo "Expires in: {$refreshResult['expires_in']} seconds\n\n";

    // 5. 验证新 Token
    echo "5. 验证新 Token...\n";
    $newPayload = KodeJwt::authenticate($newToken);
    
    echo "新 Token 验证成功:\n";
    echo "User ID: {$newPayload->uid}\n";
    echo "Username: {$newPayload->username}\n";
    echo "JTI (旧): {$verifiedPayload->jti}\n";
    echo "JTI (新): {$newPayload->jti}\n\n";

    // 6. 注销 Token
    echo "6. 注销原始 Token...\n";
    $invalidated = KodeJwt::invalidate($token);
    
    echo "Token 注销" . ($invalidated ? "成功" : "失败") . "\n";

    // 7. 尝试使用已注销的 Token
    echo "7. 尝试使用已注销的 Token...\n";
    try {
        KodeJwt::authenticate($token);
        echo "ERROR: 已注销的 Token 仍然有效!\n";
    } catch (\Kode\Jwt\Exception\TokenBlacklistedException $e) {
        echo "SUCCESS: 已注销的 Token 被正确拒绝\n";
        echo "错误信息: " . $e->getMessage() . "\n\n";
    }

    // 8. 使用新 Token
    echo "8. 使用新 Token...\n";
    $finalPayload = KodeJwt::authenticate($newToken);
    
    echo "新 Token 仍然有效:\n";
    echo "User ID: {$finalPayload->uid}\n";
    echo "Username: {$finalPayload->username}\n\n";

    echo "=== 所有示例执行完成 ===\n";

} catch (\Exception $e) {
    echo "错误: " . $e->getMessage() . "\n";
    echo "文件: " . $e->getFile() . "\n";
    echo "行号: " . $e->getLine() . "\n";
}