<?php

declare(strict_types=1);

/**
 * Kode JWT 基础使用示例（v1.8.x）
 *
 * 演示：
 * 1. JWT Token 的生成、验证、刷新、注销
 * 2. 标准声明（iss / aud / sub / nonce）的使用
 * 3. 业务声明强制校验（expected_claims）
 * 4. 时钟漂移容忍（clock_skew）
 * 5. 高熵 JTI 自动生成
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;
use Kode\Jwt\Security\AntiReplay;

echo "=== Kode JWT 基础使用示例（v1.8.x） ===\n\n";

// 1. 初始化配置
echo "1. 初始化配置（含 expected_claims 强制校验）...\n";
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
            'clock_skew' => 30,
            // 业务声明强制校验：iss/aud 必须匹配
            'expected_claims' => [
                'iss' => 'https://auth.example.com',
                'aud' => ['api.example.com', 'mobile'],
                'sub' => 'auth-service',
            ],
        ],
    ],
    'storage' => [
        'memory' => ['limit' => 10000],
    ],
    'logging' => [
        'enabled' => false,
    ],
    // 防重放配置：关闭（演示流程；生产建议开启 strict/lenient）
    'replay' => [
        'mode' => 'off',
    ],
]);
echo "配置初始化完成\n\n";

// 2. 创建 Payload 并生成 Token（带标准声明）
echo "2. 创建 Payload 并生成 Token...\n";
$now = time();
$payload = Payload::create(
    uid: 1001,
    username: 'john_doe',
    platform: 'web',
    exp: $now + 3600,
    iat: $now,
    jti: Payload::generateJti(),         // 32 字节高熵 JTI
    roles: ['user', 'admin'],
    perms: ['read', 'write', 'delete'],
    audience: ['api.example.com'],         // 业务可指定受众
    issuer: 'https://auth.example.com',   // 业务可指定签发者
    subject: 'auth-service',              // 业务可指定主体
    customData: ['tenant_id' => 'demo-tenant']
);

$result = KodeJwt::issue($payload);
$token = $result['token'];
echo "Token 生成成功\n";
echo "过期时间: {$result['expires_in']} 秒\n";
echo "Token 前 60 字符: " . substr($token, 0, 60) . "...\n\n";

// 3. 验证 Token
echo "3. 验证 Token（自动应用 expected_claims 校验）...\n";
$verified = KodeJwt::authenticate($token);
echo "验证成功\n";
echo "用户 ID: {$verified->uid}\n";
echo "用户名: {$verified->username}\n";
echo "角色: " . implode(', ', $verified->roles ?? []) . "\n";
echo "受众 (aud): " . json_encode($verified->getAudience()) . "\n";
echo "签发者 (iss): {$verified->getIssuer()}\n";
echo "主体 (sub): {$verified->getSubject()}\n";
echo "JTI: {$verified->jti}\n\n";

// 4. 演示 expected_claims 拒绝不匹配 Token
echo "4. 演示 expected_claims 强制校验（构造跨受众 Token）...\n";
$maliciousPayload = Payload::create(
    uid: 9999,
    platform: 'web',
    exp: $now + 3600,
    iat: $now,
    jti: Payload::generateJti(),
    audience: ['attacker.example.com'],   // 不在允许列表中
    issuer: 'https://auth.example.com',
    subject: 'auth-service'
);

$maliciousBuilder = (new \Kode\Jwt\Token\Builder(['algo' => 'HS256', 'secret' => 'your-secret-key-here']))
    ->fromPayload($maliciousPayload)
    ->setAudience(['attacker.example.com'])
    ->setIssuer('https://auth.example.com')
    ->setSubject('auth-service');
$maliciousToken = $maliciousBuilder->build();

try {
    KodeJwt::authenticate($maliciousToken);
    echo "错误: 恶意 Token 应当被拒绝\n";
} catch (\Kode\Jwt\Exception\TokenInvalidException $e) {
    echo "正确: 业务声明校验拒绝 — {$e->getMessage()}\n\n";
}

// 5. 刷新 Token
echo "5. 刷新 Token...\n";
$refreshed = KodeJwt::refresh($token);
echo "Token 刷新成功\n";
echo "新 Token 前 60 字符: " . substr($refreshed['token'], 0, 60) . "...\n\n";

// 6. 注销原始 Token
echo "6. 注销原始 Token...\n";
KodeJwt::invalidate($token);
echo "Token 已注销\n\n";

// 7. 验证已注销的 Token
echo "7. 验证已注销的 Token...\n";
try {
    KodeJwt::authenticate($token);
    echo "错误: 已注销的 Token 不应该有效\n";
} catch (\Kode\Jwt\Exception\TokenBlacklistedException $e) {
    echo "正确: 已注销的 Token 被拒绝\n";
    echo "异常信息: {$e->getMessage()}\n\n";
}

// 8. 使用刷新后的 Token
echo "8. 使用刷新后的 Token...\n";
$verifiedNew = KodeJwt::authenticate($refreshed['token']);
echo "刷新后的 Token 仍然有效\n";
echo "用户 ID: {$verifiedNew->uid}\n\n";

// 9. 演示一次性 Nonce 生成（防重放场景下使用）
echo "9. 生成一次性 Nonce（生产环境配合 AntiReplay 模式使用）...\n";
$nonce = AntiReplay::generateNonce(16);  // 32 字节（64 hex 字符）
echo "Nonce: {$nonce} (长度=" . strlen($nonce) . ")\n\n";

echo "=== 基础示例执行完成 ===\n";
