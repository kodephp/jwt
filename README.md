# Kode JWT：一个健壮、全面、现代化的 PHP 8.1+ JWT 包

> **项目名称**：`kode/jwt`  
> **目标**：为现代 PHP 应用提供安全、灵活、高性能的 JWT 身份验证解决方案，支持单点登录（SSO）、多点登录、黑名单管理、自动续期、多平台适配，兼容 FPM、Swoole、RoadRunner 等运行环境。

---

## 📌 项目愿景

构建一个**生产级、零侵入、高可扩展**的 JWT 包，专为 PHP 8.1+ 设计，充分利用现代 PHP 特性（如属性、联合类型、泛型模拟、反射优化），并支持主流框架（Laravel、Symfony、ThinkPHP、Hyperf、EasySwoole 等）无缝接入。
可使用kode相关包或其他通用适合的包快速集成。

---

## 🚀 核心特性

| 特性 | 说明 |
|------|------|
| ✅ **PHP 8.1+ 原生支持** | 使用 `readonly` 属性、`enum`、`never`、`true/false` 类型、`intersection types`（模拟）等新特性 |
| ✅ **多平台支持** | H5、PC、App、小程序（微信/支付宝/抖音）等，通过 `platform` 声明区分，是否启用平台，平台配置一致或单独配置 |
| ✅ **单点登录（SSO）** | 同一用户在同一平台仅允许一个有效 Token |
| ✅ **多点登录（MLO）** | 支持同一用户在多个设备同时登录 |
| ✅ **Token 黑名单** | 支持主动注销、强制下线，基于 Redis 或内存存储（协程安全） |
| ✅ **自动续期（Refresh）** | 支持滑动过期、固定刷新周期，防止频繁登录 |
| ✅ **多环境配置** | 支持 `config/jwt.php` 配置，兼容 Laravel、Hyperf 等框架 |
| ✅ **运行时兼容** | 支持 FPM、Swoole 多进程/协程、RoadRunner 多线程 |
| ✅ **类型安全 & 反射优化** | 使用 `ReflectionClass` + 缓存实现高性能依赖注入与配置解析 |
| ✅ **逆变/协变设计** | 接口设计遵循 LSP，支持泛型风格扩展（通过 PHPDoc + 命名规范） |
| ✅ **零框架依赖** | 可独立使用，也可通过适配器接入任意框架 |
| ✅ **事件驱动** | 提供 `TokenIssued`、`TokenExpired`、`TokenRevoked` 等事件钩子 |
| ✅ **审计日志** | 可选记录 Token 生成、使用、注销行为，使用通用日志包 |
| ✅ **加密算法可插拔** | 默认 `HS256` / `RS256`，支持自定义签名器 |

---

## 📁 项目结构（PSR-4）

```bash
src/
├── Contract/           # 所有接口定义
│   ├── TokenManagerInterface.php
│   ├── StorageInterface.php
│   ├── GuardInterface.php
│   └── EventInterface.php
├── Token/              # Token 核心类
│   ├── Builder.php
│   ├── Parser.php
│   ├── Claim.php
│   └── Payload.php
├── Guard/              # 守卫机制
│   ├── BaseGuard.php
│   ├── SsoGuard.php
│   └── MloGuard.php
├── Storage/            # 存储驱动
│   ├── RedisStorage.php
│   ├── MemoryStorage.php
│   └── NullStorage.php
├── Exception/          # 自定义异常
│   ├── TokenInvalidException.php
│   ├── TokenExpiredException.php
│   └── TokenBlacklistedException.php
├── Event/              # 事件系统
│   ├── TokenIssued.php
│   └── TokenRevoked.php
├── Config/             # 配置管理
│   └── ConfigLoader.php
└── KodeJwt.php         # 主门面/工厂类
```

---

## 🛠️ 安装方式

```bash
composer require kode/jwt
```

---

## 🧩 配置文件（`config/jwt.php`）

```php
<?php

return [
    'defaults' => [
        'guard' => 'api',
        'provider' => 'users',
    ],

    'guards' => [
        'api' => [
            'driver' => 'kode',
            'provider' => 'users',
            'storage' => 'redis',        // redis, memory, null
            'blacklist_enabled' => true,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,      // 分钟（2周）
            'ttl' => 1440,               // 分钟（24小时）
            'algo' => 'HS256',
            'secret' => env('JWT_SECRET'),
            'public_key' => env('JWT_PUBLIC_KEY_PATH'),
            'private_key' => env('JWT_PRIVATE_KEY_PATH'),
        ],
    ],

    'platforms' => [
        'web', 'h5', 'pc', 'app', 'wx_mini', 'ali_mini', 'tt_mini'
    ],

    'storage' => [
        'redis' => [
            'connection' => 'default',
            'prefix' => 'kode:jwt:',
        ],
        'memory' => [
            'limit' => 10000, // 最大缓存数量
        ]
    ],

    'events' => [
        'enabled' => true,
        'listeners' => [
            \App\Listeners\OnTokenIssued::class,
            \App\Listeners\OnTokenRevoked::class,
        ]
    ]
];
```

---

## 🔐 核心类设计（示例）

### `Token/Payload.php`

```php
namespace Kode\Jwt\Token;

use Kode\Jwt\Contract\Arrayable;

final readonly class Payload implements Arrayable
{
    public function __construct(
        public int $uid,
        public string $username,
        public string $platform,
        public int $exp,
        public int $iat,
        public string $jti,
        public ?array $roles = null,
        public ?array $perms = null,
        public array $custom = []
    ) {}

    public function toArray(): array
    {
        return get_object_vars($this);
    }
    
    /**
     * 从数组创建Payload实例
     * 
     * @param array $data 包含Payload数据的数组
     * @return static
     * @throws \InvalidArgumentException 当必需字段缺失时抛出异常
     */
    public static function fromArray(array $data): static
    {
        // 验证必需字段
        $requiredFields = ['uid', 'username', 'platform', 'exp', 'iat', 'jti'];
        foreach ($requiredFields as $field) {
            if (!isset($data[$field])) {
                throw new \InvalidArgumentException("Missing required field: {$field}");
            }
        }

        return new static(
            (int) $data['uid'],
            (string) $data['username'],
            (string) $data['platform'],
            (int) $data['exp'],
            (int) $data['iat'],
            (string) $data['jti'],
            isset($data['roles']) ? (array) $data['roles'] : null,
            isset($data['perms']) ? (array) $data['perms'] : null,
            isset($data['custom']) ? (array) $data['custom'] : []
        );
    }
    
    /**
     * 创建一个包含自定义数据的Payload实例
     * 
     * @param int $uid 用户ID
     * @param string $username 用户名
     * @param string $platform 平台标识
     * @param int $exp 过期时间戳
     * @param int $iat 签发时间戳
     * @param string $jti JWT ID
     * @param array|null $roles 用户角色列表
     * @param array|null $perms 用户权限列表
     * @param array|string|null $customData 自定义数据，可以是数组或加密字符串
     * @return static
     */
    public static function create(
        int $uid,
        string $username,
        string $platform,
        int $exp,
        int $iat,
        string $jti,
        ?array $roles = null,
        ?array $perms = null,
        array|string|null $customData = null
    ): static {
        $custom = [];
        
        // 处理自定义数据
        if (is_string($customData)) {
            // 如果是字符串，将其存储为加密数据
            $custom['encrypted_data'] = $customData;
        } elseif (is_array($customData)) {
            // 如果是数组，直接合并到custom字段
            $custom = $customData;
        }
        
        return new static(
            $uid,
            $username,
            $platform,
            $exp,
            $iat,
            $jti,
            $roles,
            $perms,
            $custom
        );
    }
}
```

### Payload增强功能详解

Payload类现在支持更灵活的自定义数据处理和更健壮的方法实现：

#### 1. 灵活的自定义数据处理

Payload类提供了两种方式来处理自定义数据：

##### 使用`create()`静态方法（推荐）

```php
// 1. 使用数组自定义数据
$payload = Payload::create(
    uid: 456,
    username: 'jane_doe',
    platform: 'web',
    exp: time() + 3600,
    iat: time(),
    jti: uniqid('jwt_'),
    roles: ['user', 'editor'],
    perms: ['read', 'write'],
    customData: [
        'department' => 'Marketing',
        'level' => 3,
        'preferences' => [
            'theme' => 'dark',
            'language' => 'zh-CN'
        ]
    ]
);

// 2. 使用加密字符串自定义数据
$encryptedData = base64_encode(json_encode([
    'sensitive_info' => 'secret_data',
    'timestamp' => time()
]));

$payload = Payload::create(
    uid: 789,
    username: 'bob_smith',
    platform: 'mobile',
    exp: time() + 3600,
    iat: time(),
    jti: uniqid('jwt_'),
    roles: ['user'],
    perms: ['read'],
    customData: $encryptedData
);
```

##### 使用`fromArray()`方法

```php
// 从数组创建Payload（包含必需字段验证）
$data = [
    'uid' => 123,
    'username' => 'john_doe',
    'platform' => 'app',
    'exp' => time() + 3600,
    'iat' => time(),
    'jti' => uniqid('jwt_'),
    'roles' => ['user'],
    'perms' => ['read', 'write'],
    'custom' => [
        'department' => 'IT',
        'location' => 'Beijing'
    ]
];

$payload = Payload::fromArray($data);
```

#### 2. 增强的方法实现

Payload类提供了丰富的方法来操作和检查Payload数据：

##### 自定义数据操作方法

```php
// 获取所有自定义数据
$customData = $payload->getCustomData();

// 获取特定自定义数据
$department = $payload->getCustom('department', 'Unknown');

// 检查是否存在特定自定义数据
if ($payload->hasCustom('department')) {
    echo "Department: " . $payload->getCustom('department');
}

// 获取加密的自定义数据
$encryptedData = $payload->getEncryptedData();

// 检查是否存在加密的自定义数据
if ($payload->hasEncryptedData()) {
    $data = json_decode(base64_decode($encryptedData), true);
    // 处理解密后的数据
}
```

##### 角色和权限检查方法

```php
// 检查用户是否具有指定角色（使用严格比较）
if ($payload->hasRole('admin')) {
    // 用户具有管理员角色
}

// 检查用户是否具有指定权限（使用严格比较）
if ($payload->hasPermission('delete')) {
    // 用户具有删除权限
}
```

##### 其他实用方法

```php
// 获取用户信息
$userInfo = $payload->getUserInfo();

// 检查Token是否已过期
if ($payload->isExpired()) {
    // Token已过期
}

// 获取剩余有效时间
$ttl = $payload->getTtl();

// 获取用户标识
$userIdentifier = $payload->getUserIdentifier();
```

---

### `Guard/SsoGuard.php`（单点登录）

```php
namespace Kode\Jwt\Guard;

use Kode\Jwt\Contract\GuardInterface;
use Kode\Jwt\Storage\StorageInterface;

class SsoGuard implements GuardInterface
{
    public function __construct(
        private StorageInterface $storage
    ) {}

    public function isUnique(string $uid, string $platform): bool
    {
        $key = "sso:{$uid}:{$platform}";
        $existing = $this->storage->get($key);
        
        if ($existing) {
            // 可选：自动踢出旧 Token
            $this->storage->blacklist($existing);
            $this->storage->delete($key);
        }

        return true;
    }

    public function register(string $uid, string $platform, string $jti): void
    {
        $this->storage->set(
            "sso:{$uid}:{$platform}",
            $jti,
            config('jwts.guards.api.ttl')
        );
    }
}
```

---

### `Storage/RedisStorage.php`（协程安全）

```php
namespace Kode\Jwt\Storage;

use Swoole\Coroutine\Redis as CoRedis;

class RedisStorage implements StorageInterface
{
    private ?CoRedis $redis = null;

    public function __construct()
    {
        $this->connect();
    }

    private function connect(): void
    {
        $config = config('jwts.storage.redis');
        $this->redis = new CoRedis();
        $this->redis->connect('127.0.0.1', 6379);
        $this->redis->auth($config['password'] ?? '');
        $this->redis->select($config['db'] ?? 0);
    }

    public function blacklist(string $jti, int $ttl = 3600): bool
    {
        return (bool)$this->redis->setex(
            "blacklist:{$jti}",
            $ttl,
            '1'
        );
    }

    public function isBlacklisted(string $jti): bool
    {
        return (bool)$this->redis->exists("blacklist:{$jti}");
    }
}
```

---

## 🧪 使用示例（Laravel / Hyperf）

### 1. 生成 Token

```php
use Kode\Jwt\KodeJwt;

$payload = new Payload(
    uid: 123,
    username: 'john_doe',
    platform: 'app',
    exp: now()->addMinutes(1440)->getTimestamp(),
    iat: now()->getTimestamp(),
    jti: uniqid('jwt_'),
    roles: ['user'],
    perms: ['read', 'write']
);

$token = KodeJwt::guard('api')->issue($payload);

// 返回: ['token' => 'eyJ...', 'expires_in' => 1440, 'refresh_ttl' => 20160]
```

### 2. 验证 Token

```php
try {
    $payload = KodeJwt::guard('api')->authenticate($token);
    echo $payload->username; // john_doe
} catch (TokenInvalidException $e) {
    // 处理异常
}
```

### 3. 刷新 Token

```php
$newToken = KodeJwt::guard('api')->refresh($oldToken);
```

### 4. 注销 Token（加入黑名单）

```php
KodeJwt::guard('api')->invalidate($token);
```

### 5. 使用便捷方法

```php
// 使用Builder的便捷方法
$token = KodeJwt::builder()
    ->setUid(123)
    ->setUsername('john_doe')
    ->setPlatform('app')
    ->setRoles(['user'])
    ->setPermissions(['read', 'write'])
    ->setCustom(['department' => 'IT'])
    ->issue();

// 获取用户的所有活跃Token
$tokens = KodeJwt::getUserTokens('123', 'app');

// 强制注销用户的所有Token
$count = KodeJwt::revokeUserTokens('123', 'app');

// 检查Token是否有效
$isValid = KodeJwt::isTokenValid($token);

// 使用增强的Payload创建方法
// 1. 使用数组自定义数据
$payload = Payload::create([
    'uid' => 456,
    'username' => 'jane_doe',
    'platform' => 'web'
], [
    'department' => 'Marketing',
    'level' => 3,
    'preferences' => [
        'theme' => 'dark',
        'language' => 'zh-CN'
    ]
]);

// 2. 使用加密字符串自定义数据
$encryptedData = base64_encode(json_encode([
    'sensitive_info' => 'secret_data',
    'timestamp' => time()
]));

$payload = Payload::create([
    'uid' => 789,
    'username' => 'bob_smith',
    'platform' => 'mobile'
], $encryptedData);
```

---

## ⚙️ 多运行时支持

| 环境 | 支持 | 说明 |
|------|------|------|
| PHP-FPM | ✅ | 使用 Redis 或数据库存储黑名单 |
| Swoole 协程 | ✅ | 使用 `Swoole\Coroutine\Redis`，避免连接泄露 |
| RoadRunner | ✅ | 配合 `spiral/roadrunner-jobs` 实现异步清理 |
| ReactPHP | ⚠️ | 需适配异步存储驱动（未来计划） |

---

## 🔍 安全与性能优化

- **JTI 防重放**：每个 Token 唯一 `jti`，加入黑名单防止重放攻击
- **平台隔离**：不同平台 Token 不互通
- **签名安全**：推荐使用 `RS256` 非对称加密
- **反射缓存**：使用 `OpCache` + `ReflectionClass` 缓存配置解析
- **内存优化**：避免大对象引用，使用 `readonly` 减少复制开销

---

## 🧩 扩展建议（IDE 友好）

### 1. 使用 PHPStan / Psalm 进行静态分析

```json
// phpstan.neon
parameters:
    level: 12
    paths:
        - src
```

### 2. IDE Helper（生成 `ide-helper.php`）

```php
// 供 IDE 识别静态门面
/** @method static \Kode\Jwt\Token\Payload authenticate(string $token) */
/** @method static string issue(\Kode\Jwt\Token\Payload $payload) */
class KodeJwt {}
```

---

## 📈 未来规划

- [ ] 支持 JWT 多签（Detached Signature）
- [ ] 集成 OpenID Connect 支持
- [ ] 提供 CLI 工具管理 Token，生成密钥对
- [ ] 支持 JWT 与 OAuth2 混合模式
- [ ] 提供 Prometheus 监控指标（Token 数量、刷新频率等）

---

## 🤝 贡献与反馈

欢迎提交 Issue 或 PR！  
GitHub: `https://github.com/kode-php/jwt`

---

> **命名原则**：避免与 PHP 原生 `jwt_*` 函数冲突，使用 `KodeJwt` 前缀，类名清晰表达职责，方法名动词开头（`issue`, `authenticate`, `refresh`, `invalidate`）。

> **逆变/协变示例**：  
> `StorageInterface` 作为协变返回类型，`GuardInterface` 可接收更具体的 `Payload` 子类（通过泛型模拟）。

---

🎯 **目标达成**：  
一个**安全、健壮、易用、高性能**的 JWT 包，适用于从传统 FPM 到现代协程项目的全场景需求。