<?php

declare(strict_types=1);

/**
 * Kode JWT 高级使用示例
 *
 * 展示多签、OpenID Connect、OAuth2、密钥轮换、Prometheus 监控等高级功能
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Enum\Algorithm;
use Kode\Jwt\Enum\StorageType;
use Kode\Jwt\OAuth2\HybridProvider;
use Kode\Jwt\Metrics\PrometheusMetrics;
use Kode\Jwt\Support\PhpFeature;

echo "=== Kode JWT 高级使用示例 ===\n\n";

// 1. PHP 版本特性检测
echo "1. PHP 版本特性检测...\n";
$phpInfo = PhpFeature::getVersionInfo();
echo "PHP 版本: {$phpInfo['version']}\n";
echo "支持枚举: " . ($phpInfo['features']['enum'] ? '是' : '否') . "\n";
echo "支持 readonly 类: " . ($phpInfo['features']['readonly_class'] ? '是' : '否') . "\n";
echo "支持管道操作符: " . ($phpInfo['features']['pipe_operator'] ? '是' : '否') . "\n\n";

// 2. 枚举使用示例
echo "2. 枚举使用示例...\n";
$hmacAlgos = array_map(fn(Algorithm $a) => $a->value, Algorithm::hmacAlgorithms());
echo "HMAC 算法: " . implode(', ', $hmacAlgos) . "\n";
echo "RS256 是否为非对称算法: " . (Algorithm::RS256->isAsymmetric() ? '是' : '否') . "\n";
echo "Redis 存储是否持久化: " . (StorageType::REDIS->isPersistent() ? '是' : '否') . "\n\n";

// 3. OAuth2 混合模式
echo "3. OAuth2 混合模式示例...\n";
KodeJwt::init([
    'guards' => ['api' => ['driver' => 'sso', 'storage' => 'memory', 'secret' => 'oauth2-secret']],
    'storage' => ['memory' => ['limit' => 1000]],
]);

$oauth2Provider = new HybridProvider([
    'secret' => 'oauth2-secret-key',
    'access_token_ttl' => 3600,
    'issuer' => 'https://example.com',
]);

$tokens = $oauth2Provider->generateAuthorizationCodeTokens(
    clientId: 'client-app',
    userId: 12345,
    scopes: ['openid', 'profile']
);
echo "Access Token: " . substr($tokens->accessToken, 0, 50) . "...\n";
echo "Token 类型: {$tokens->tokenType}\n";
echo "过期时间: {$tokens->expiresIn} 秒\n\n";

// 4. Prometheus 监控指标
echo "4. Prometheus 监控指标示例...\n";
$metrics = new PrometheusMetrics('kode_jwt');
$metrics->recordTokenIssued('api', 'web');
$metrics->recordTokenAuthenticated('api');
$metrics->setActiveTokens(150, 'api');

$result = $metrics->timeOperation('authenticate', function () {
    usleep(1000);
    return 'success';
});
echo "操作结果: {$result}\n";
echo "指标已记录\n\n";

// 5. 多签 JWT（需要配置）
echo "5. 多签 JWT 示例...\n";
echo "多签功能需要配置多个签名者密钥\n";
echo "使用 Builder::buildMultiSignature() 方法\n\n";

// 6. 角色权限检查
echo "6. 角色权限检查示例...\n";
KodeJwt::init([
    'guards' => ['api' => ['driver' => 'sso', 'storage' => 'memory', 'secret' => 'role-secret']],
    'storage' => ['memory' => ['limit' => 1000]],
]);

$rbacPayload = Payload::create(
    uid: 2001,
    username: 'admin_user',
    platform: 'admin',
    exp: time() + 3600,
    iat: time(),
    jti: bin2hex(random_bytes(16)),
    roles: ['admin', 'editor'],
    perms: ['read', 'write', 'delete']
);

echo "用户角色: " . implode(', ', $rbacPayload->roles ?? []) . "\n";
echo "是否有 admin 角色: " . ($rbacPayload->hasRole('admin') ? '是' : '否') . "\n";
echo "是否有 delete 权限: " . ($rbacPayload->hasPermission('delete') ? '是' : '否') . "\n\n";

// 7. 自定义数据存储
echo "7. 自定义数据存储示例...\n";
$customPayload = Payload::create(
    uid: 3001,
    username: 'custom_user',
    platform: 'mobile',
    exp: time() + 3600,
    iat: time(),
    jti: bin2hex(random_bytes(16)),
    customData: [
        'department' => 'IT',
        'level' => 5,
        'preferences' => ['theme' => 'dark', 'lang' => 'zh-CN']
    ]
);

echo "自定义数据: " . json_encode($customPayload->getCustomData(), JSON_UNESCAPED_UNICODE) . "\n";
echo "部门: " . $customPayload->getCustom('department') . "\n";
echo "等级: " . $customPayload->getCustom('level') . "\n\n";

echo "=== 高级示例执行完成 ===\n";
