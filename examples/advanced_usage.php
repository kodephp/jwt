<?php

/**
 * Kode JWT 高级使用示例
 * 展示如何使用增强的Payload功能
 */

// 引入自动加载文件
require_once __DIR__ . '/../vendor/autoload.php';

use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

// 设置配置
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
            'secret' => 'example_secret_key_for_advanced_usage',
        ],
    ],
    'storage' => [
        'memory' => [
            'limit' => 10000,
        ]
    ],
]);

try {
    echo "=== Kode JWT 高级使用示例 ===\n\n";

    // 1. 使用create方法创建包含数组自定义数据的Payload
    echo "1. 使用create方法创建包含数组自定义数据的Payload...\n";
    $payload1 = Payload::create(
        uid: 456,
        username: 'jane_doe',
        platform: 'web',
        exp: time() + 3600,
        iat: time(),
        jti: uniqid('jwt_', true),
        roles: ['user', 'editor'],
        perms: ['read', 'write'],
        customData: [
            'department' => 'Marketing',
            'level' => 3,
            'preferences' => ['theme' => 'dark', 'language' => 'zh-CN']
        ]
    );
    
    echo "Payload 创建成功\n";
    echo "自定义数据: " . json_encode($payload1->getCustomData()) . "\n\n";

    // 2. 使用create方法创建包含加密字符串的Payload
    echo "2. 使用create方法创建包含加密字符串的Payload...\n";
    $encryptedData = base64_encode(json_encode(['sensitive_info' => 'secret_data', 'timestamp' => time()]));
    $payload2 = Payload::create(
        uid: 789,
        username: 'bob_smith',
        platform: 'mobile',
        exp: time() + 7200,
        iat: time(),
        jti: uniqid('jwt_', true),
        roles: ['user'],
        perms: ['read'],
        customData: $encryptedData  // 传入加密字符串
    );
    
    echo "Payload 创建成功\n";
    echo "是否有加密数据: " . ($payload2->hasEncryptedData() ? '是' : '否') . "\n";
    echo "加密数据: " . $payload2->getEncryptedData() . "\n\n";

    // 3. 生成Token并验证
    echo "3. 生成Token并验证...\n";
    $result1 = KodeJwt::issue($payload1);
    $token1 = $result1['token'];
    
    echo "Token 生成成功:\n";
    echo "Token: {$token1}\n\n";

    // 4. 验证Token并访问自定义数据
    echo "4. 验证Token并访问自定义数据...\n";
    $verifiedPayload = KodeJwt::authenticate($token1);
    
    echo "Token 验证成功:\n";
    echo "User ID: {$verifiedPayload->uid}\n";
    echo "Username: {$verifiedPayload->username}\n";
    echo "Department: " . $verifiedPayload->getCustom('department') . "\n";
    echo "Level: " . $verifiedPayload->getCustom('level') . "\n";
    echo "Preferences: " . json_encode($verifiedPayload->getCustom('preferences')) . "\n";
    echo "是否有加密数据: " . ($verifiedPayload->hasEncryptedData() ? '是' : '否') . "\n\n";

    // 5. 演示角色和权限检查
    echo "5. 演示角色和权限检查...\n";
    echo "是否有 'user' 角色: " . ($verifiedPayload->hasRole('user') ? '是' : '否') . "\n";
    echo "是否有 'admin' 角色: " . ($verifiedPayload->hasRole('admin') ? '是' : '否') . "\n";
    echo "是否有 'read' 权限: " . ($verifiedPayload->hasPermission('read') ? '是' : '否') . "\n";
    echo "是否有 'delete' 权限: " . ($verifiedPayload->hasPermission('delete') ? '是' : '否') . "\n\n";

    // 6. 演示健壮的fromArray方法
    echo "6. 演示健壮的fromArray方法...\n";
    $data = [
        'uid' => 999,
        'username' => 'test_user',
        'platform' => 'api',
        'exp' => time() + 1800,
        'iat' => time(),
        'jti' => uniqid('jwt_', true),
        'roles' => ['user', 'tester'],
        'perms' => ['read', 'test'],
        'custom' => ['project' => 'jwt_package', 'version' => '1.0']
    ];
    
    $payload3 = Payload::fromArray($data);
    echo "从数组创建Payload成功:\n";
    echo "User ID: {$payload3->uid}\n";
    echo "Project: " . $payload3->getCustom('project') . "\n\n";

    // 7. 演示缺失必需字段的错误处理
    echo "7. 演示缺失必需字段的错误处理...\n";
    try {
        $incompleteData = [
            'username' => 'incomplete_user',
            'platform' => 'api',
            'exp' => time() + 1800,
            'iat' => time(),
            'jti' => uniqid('jwt_', true)
        ];
        
        Payload::fromArray($incompleteData);
    } catch (InvalidArgumentException $e) {
        echo "捕获到预期的异常: " . $e->getMessage() . "\n\n";
    }

    echo "=== 高级使用示例执行完成 ===\n";

} catch (Exception $e) {
    echo "错误: " . $e->getMessage() . "\n";
    echo "文件: " . $e->getFile() . "\n";
    echo "行号: " . $e->getLine() . "\n";
}