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

### CLI 工具初始化

安装完成后，在你的项目根目录运行以下命令来生成配置文件和密钥：

```bash
# 进入你的项目目录
cd /path/to/your/project

# 安装配置文件和生成密钥（RSA 密钥对 + HMAC 密钥）
php vendor/bin/jwt install

# 或者仅生成配置文件
php vendor/bin/jwt install --config-only

# 或者仅生成密钥
php vendor/bin/jwt install --key-only

# 强制覆盖已存在的文件
php vendor/bin/jwt install --force
```

### CLI 命令详解

| 命令 | 说明 | 示例 |
|------|------|------|
| `jwt install` 或 `jwt i` | 安装配置文件并生成密钥 | `php jwt install` |
| `jwt key` 或 `jwt k` | 生成密钥对 | `php jwt key rsa` |
| `jwt help` 或 `jwt h` | 显示帮助信息 | `php jwt help` |

#### install 命令选项

| 选项 | 说明 |
|------|------|
| `--config-only` | 仅发布配置文件，不生成密钥 |
| `--key-only` | 仅生成密钥，不发布配置文件 |
| `--force` | 强制覆盖已存在的文件 |
| `--platform=<name>` | 指定默认平台（默认: web） |

#### key 命令选项

| 参数 | 说明 |
|------|------|
| `rsa` | 生成 RSA 密钥对（默认） |
| `hmac` | 生成 HMAC 密钥 |
| `stdout` | 输出到标准输出（而非文件） |
| `file` | 保存到文件（默认） |
| `--force` | 强制覆盖已存在的密钥文件 |

**示例**：

```bash
# 生成 RSA 密钥对（默认）
php jwt key rsa

# 生成 HMAC 密钥
php jwt key hmac

# 生成并输出到控制台
php jwt key rsa stdout

# 强制覆盖现有密钥
php jwt key rsa --force
```

### 生成的文件结构

运行 `php jwt install` 后，会在你的项目目录中生成以下文件：

```
your-project/
├── config/
│   └── jwt.php          # JWT 配置文件
└── storage/
    └── keys/
        ├── secret       # HMAC 密钥（用于 HS256）
        ├── private.pem  # RSA 私钥（用于 RS256 签名）
        └── public.pem   # RSA 公钥（用于 RS256 验证）
```

> **重要**：请确保 `storage/keys/` 目录不在版本控制中（添加到 `.gitignore`），以保护密钥安全。

---

## 🧩 配置文件（`config/jwt.php`）

运行 `php jwt install` 后，会自动生成配置文件。以下是完整配置说明：

```php
<?php

declare(strict_types=1);

/**
 * JWT 配置文件
 * 由 kode/jwt CLI 工具生成
 *
 * @generated_at 2025-12-30 09:14:47
 */

return [
    /**
     * 默认配置
     */
    'defaults' => [
        'guard' => 'api',         // 默认守卫名称
        'provider' => 'users',    // 默认用户提供者
        'platform' => 'web',      // 默认平台
    ],

    /**
     * 守卫配置
     * 每个守卫对应一种认证策略
     */
    'guards' => [
        'api' => [
            'driver' => 'kode',           // 驱动类型（固定为 kode）
            'provider' => 'users',        // 用户提供者
            'storage' => 'redis',         // 存储驱动：redis, memory, null
            'blacklist_enabled' => true,  // 是否启用黑名单
            'refresh_enabled' => true,    // 是否支持自动续期
            'refresh_ttl' => 20160,       // 续期窗口（分钟，默认2周）
            'ttl' => 1440,                // Token 有效期（分钟，默认24小时）
            'algo' => 'RS256',            // 加密算法：RS256, HS256
            'secret' => null,             // HMAC 密钥（RS256 可为 null）
            'public_key' => null,         // RSA 公钥路径或内容
            'private_key' => null,        // RSA 私钥路径或内容
        ],
    ],

    /**
     * 平台配置
     * 用于多平台 Token 隔离
     */
    'platforms' => [
        'web' => [
            'enabled' => true,
            'guard' => 'api',
            'ttl' => 1440,
        ],
        'h5' => [
            'enabled' => true,
            'guard' => 'api',
            'ttl' => 1440,
        ],
        'pc' => [
            'enabled' => true,
            'guard' => 'api',
            'ttl' => 1440,
        ],
        'app' => [
            'enabled' => true,
            'guard' => 'api',
            'ttl' => 1440,
        ],
        'wx_mini' => [
            'enabled' => true,
            'guard' => 'api',
            'ttl' => 1440,
        ],
        'ali_mini' => [
            'enabled' => true,
            'guard' => 'api',
            'ttl' => 1440,
        ],
        'tt_mini' => [
            'enabled' => true,
            'guard' => 'api',
            'ttl' => 1440,
        ],
    ],

    /**
     * SSO 配置
     * 单点登录：同一用户在同一平台仅允许一个有效 Token
     */
    'sso' => [
        'enabled' => false,              // 是否启用 SSO
        'scope' => 'platform',           // 隔离范围：platform（平台级）, guard（守卫级）
    ],

    /**
     * MLO 配置
     * 多点登录：支持同一用户多个设备同时在线
     */
    'mlo' => [
        'enabled' => false,              // 是否启用 MLO
        'max_devices' => 5,              // 最大设备数
        'kick_old' => false,             // 是否踢掉旧设备
    ],

    /**
     * 存储配置
     */
    'storage' => [
        'redis' => [
            'connection' => 'default',   // Redis 连接名称
            'prefix' => 'kode:jwt:',     // Key 前缀
        ],
        'memory' => [
            'limit' => 10000,            // 最大缓存数量
        ],
    ],

    /**
     * 事件配置
     */
    'events' => [
        'enabled' => true,
        'listeners' => [
            // \App\Listeners\OnTokenIssued::class,
            // \App\Listeners\OnTokenRevoked::class,
        ],
    ],
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
        public int|string|null $uid = null,
        public ?string $username = null,
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
        $requiredFields = ['platform', 'exp', 'iat', 'jti'];
        foreach ($requiredFields as $field) {
            if (!isset($data[$field])) {
                throw new \InvalidArgumentException("Missing required field: {$field}");
            }
        }

        return new static(
            $data['uid'] ?? null,
            $data['username'] ?? null,
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
     * @param int|string|null $uid 用户ID（支持雪花ID等字符串类型）
     * @param string|null $username 用户名
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

// 获取Token详细信息
$info = KodeJwt::getTokenInfo($token);
// 返回: ['uid' => 123, 'platform' => 'app', 'exp' => 1234567890, ...]

// 清理过期的Token
$cleanedCount = KodeJwt::cleanExpired();

// 获取存储统计信息
$stats = KodeJwt::getStats();
// 返回: ['total' => 100, 'expired' => 20, 'active' => 80]

// 使用增强的Payload创建方法
// 1. 使用数组自定义数据
$payload = Payload::create(
    uid: 456,
    username: 'jane_doe',
    platform: 'web',
    exp: time() + 86400,
    iat: time(),
    jti: uniqid('jwt_'),
    roles: ['user'],
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
    exp: time() + 86400,
    iat: time(),
    jti: uniqid('jwt_'),
    customData: $encryptedData
);
```

---

## ⚙️ 多运行时支持

| 环境 | 支持 | 说明 |
|------|------|------|
| PHP-FPM | ✅ | 使用 Redis 或数据库存储黑名单 |
| Swoole 协程 | ✅ | 使用 `Swoole\Coroutine\Redis`，避免连接泄露 |
| RoadRunner | ✅ | 配合 `spiral/roadrunner-jobs` 实现异步清理 |

---

## 🔍 安全与性能优化

- **JTI 防重放**：每个 Token 唯一 `jti`，加入黑名单防止重放攻击
- **平台隔离**：不同平台 Token 不互通
- **签名安全**：推荐使用 `RS256` 非对称加密
- **反射缓存**：使用 `OpCache` + `ReflectionClass` 缓存配置解析
- **内存优化**：避免大对象引用，使用 `readonly` 减少复制开销
- **敏感数据保护**：支持自定义加密数据字段，用户可自行实现加解密逻辑
- **灵活字段设计**：`uid` 和 `username` 字段变为可选，支持雪花 ID 等字符串类型
- **数据最小化**：仅包含必要字段，减少 Token 体积和传输成本

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
- [ ] 实现 JWT 密钥轮换机制，支持平滑过渡

---

## 🤝 贡献与反馈

欢迎提交 Issue 或 PR！  
GitHub: `https://github.com/kode-php/jwt`

---

> **命名原则**：避免与 PHP 原生 `jwt_*` 函数冲突，使用 `KodeJwt` 前缀，类名清晰表达职责，方法名动词开头（`issue`, `authenticate`, `refresh`, `invalidate`）。

> **逆变/协变示例**：  
> `StorageInterface` 作为协变返回类型，`GuardInterface` 可接收更具体的 `Payload` 子类（通过泛型模拟）。

---

🎯 **目标达成**：  ---

## 🛠️ 框架集成指南

### Laravel 集成

#### 1. 安装配置

```bash
# 安装依赖
composer require kode/jwt

# 发布配置文件（会生成 config/jwt.php）
php artisan jwt:install

# 生成密钥
php artisan jwt:key
```

#### 2. 配置说明

`config/jwt.php`:

```php
<?php

declare(strict_types=1);

return [
    'defaults' => [
        'guard' => 'api',
        'provider' => 'users',
        'platform' => 'web',
    ],

    'guards' => [
        'api' => [
            'driver' => 'sso',
            'provider' => 'users',
            'storage' => 'redis',
            'blacklist_enabled' => true,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'ttl' => 1440,
            'algo' => 'RS256',
            'public_key' => storage_path('keys/public.pem'),
            'private_key' => storage_path('keys/private.pem'),
        ],
    ],

    'storage' => [
        'redis' => [
            'connection' => 'default',
            'prefix' => 'kode:jwt:',
        ],
    ],
];
```

#### 3. 服务提供者注册

`app/Providers/JwtServiceProvider.php`:

```php
<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Kode\Jwt\KodeJwt;

class JwtServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton('kode.jwt', function ($app) {
            KodeJwt::detectAndLoadConfig();
            return KodeJwt::guard();
        });
    }

    public function boot(): void
    {
        // 发布配置文件
        $this->publishes([
            __DIR__ . '/../../config/jwt.php' => config_path('jwt.php'),
        ], 'jwt-config');
    }
}
```

#### 4. 中间件使用

`app/Http/Middleware/JwtAuthMiddleware.php`:

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Kode\Jwt\KodeJwt;
use Symfony\Component\HttpFoundation\Response;

class JwtAuthMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['error' => '未提供 Token'], 401);
        }

        try {
            $payload = KodeJwt::authenticate($token);
            $request->merge(['jwt_payload' => $payload]);
            return $next($request);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 401);
        }
    }
}
```

注册中间件：

```php
// app/Http/Kernel.php
protected $routeMiddleware = [
    'jwt.auth' => \App\Http\Middleware\JwtAuthMiddleware::class,
];
```

#### 5. 控制器中使用

```php
<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

class AuthController extends Controller
{
    public function login()
    {
        $credentials = request()->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        // 验证用户凭据
        $user = User::where('email', $credentials['email'])->first();
        
        if (!$user || !password_verify($credentials['password'], $user->password)) {
            return response()->json(['error' => '凭据无效'], 401);
        }

        // 生成 Token
        $payload = Payload::create(
            uid: $user->id,
            username: $user->name,
            platform: 'web',
            exp: time() + 86400,
            iat: time(),
            jti: uniqid('jwt_'),
            roles: [$user->role],
        );

        $result = KodeJwt::issue($payload);

        return response()->json([
            'token' => $result['token'],
            'expires_in' => $result['expires_in'],
        ]);
    }

    public function me()
    {
        $payload = request()->get('jwt_payload');
        return response()->json([
            'id' => $payload->uid,
            'username' => $payload->username,
        ]);
    }

    public function refresh()
    {
        $token = request()->bearerToken();
        $result = KodeJwt::refresh($token);
        return response()->json([
            'token' => $result['token'],
            'expires_in' => $result['expires_in'],
        ]);
    }

    public function logout()
    {
        $token = request()->bearerToken();
        KodeJwt::invalidate($token);
        return response()->json(['message' => '已注销']);
    }
}
```

路由定义：

```php
// routes/api.php
Route::prefix('auth')->group(function () {
    Route::post('/login', [AuthController::class, 'login']);
    Route::middleware('jwt.auth')->group(function () {
        Route::get('/me', [AuthController::class, 'me']);
        Route::post('/refresh', [AuthController::class, 'refresh']);
        Route::post('/logout', [AuthController::class, 'logout']);
    });
});
```

---

### Hyperf 集成

#### 1. 安装配置

```bash
composer require kode/jwt
```

#### 2. 配置文件

`config/autoload/jwt.php`:

```php
<?php

declare(strict_types=1);

return [
    'defaults' => [
        'guard' => 'api',
        'provider' => 'users',
        'platform' => 'api',
    ],

    'guards' => [
        'api' => [
            'driver' => 'sso',
            'provider' => 'users',
            'storage' => 'coroutine_redis',
            'blacklist_enabled' => true,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'ttl' => 1440,
            'algo' => 'RS256',
            'public_key' => BASE_PATH . '/storage/keys/public.pem',
            'private_key' => BASE_PATH . '/storage/keys/private.pem',
        ],
    ],

    'storage' => [
        'coroutine_redis' => [
            'host' => '127.0.0.1',
            'port' => 6379,
            'password' => null,
            'database' => 0,
            'prefix' => 'kode:jwt:',
        ],
    ],
];
```

#### 3. 协程安全的使用方式

```php
<?php

declare(strict_types=1);

namespace App\Controller;

use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\HttpServer\Contract\ResponseInterface;
use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

class AuthController
{
    public function login(RequestInterface $request, ResponseInterface $response)
    {
        $credentials = $request->all();

        // 验证用户（示例）
        $user = $this->validateUser($credentials);

        // 生成 Token
        $payload = Payload::create(
            uid: $user['id'],
            username: $user['name'],
            platform: 'api',
            exp: time() + 86400,
            iat: time(),
            jti: uniqid('jwt_'),
            roles: [$user['role'] ?? 'user'],
        );

        $result = KodeJwt::issue($payload);

        return $response->json([
            'code' => 0,
            'data' => [
                'token' => $result['token'],
                'expires_in' => $result['expires_in'],
            ],
        ]);
    }

    public function user(RequestInterface $request)
    {
        $payload = $request->getAttribute('jwt_payload');

        return [
            'code' => 0,
            'data' => [
                'id' => $payload->uid,
                'username' => $payload->username,
            ],
        ];
    }

    private function validateUser(array $credentials): array
    {
        // 实现用户验证逻辑
        return [
            'id' => 1,
            'name' => 'test_user',
            'role' => 'admin',
        ];
    }
}
```

#### 4. 中间件

`app/Middleware/JwtAuthMiddleware.php`:

```php
<?php

declare(strict_types=1);

namespace App\Middleware;

use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\HttpServer\Contract\ResponseInterface;
use Psr\Http\Message\ResponseInterface as PsrResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Kode\Jwt\KodeJwt;

class JwtAuthMiddleware
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): PsrResponseInterface
    {
        $token = $request->getHeader('Authorization')[0] ?? '';

        if (!$token) {
            return (new ResponseInterface())->json([
                'code' => 401,
                'message' => '未提供 Token',
            ]);
        }

        $token = str_replace('Bearer ', '', $token);

        try {
            $payload = KodeJwt::authenticate($token);
            
            // 将 payload 添加到请求属性中
            $request = $request->withAttribute('jwt_payload', $payload);
            
            return $handler->handle($request);
        } catch (\Exception $e) {
            return (new ResponseInterface())->json([
                'code' => 401,
                'message' => $e->getMessage(),
            ]);
        }
    }
}
```

注册中间件：

```php
// config/autoload/middlewares.php
return [
    'http' => [
        \App\Middleware\JwtAuthMiddleware::class,
    ],
];
```

---

### ThinkPHP 集成

#### 1. 安装配置

```bash
composer require kode/jwt
```

#### 2. 配置文件

`config/jwt.php`:

```php
<?php

declare(strict_types=1);

return [
    'defaults' => [
        'guard' => 'api',
        'provider' => 'users',
        'platform' => 'web',
    ],

    'guards' => [
        'api' => [
            'driver' => 'sso',
            'provider' => 'users',
            'storage' => 'redis',
            'blacklist_enabled' => true,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'ttl' => 1440,
            'algo' => 'RS256',
            'public_key' => runtime_path() . 'keys/public.pem',
            'private_key' => runtime_path() . 'keys/private.pem',
        ],
    ],

    'storage' => [
        'redis' => [
            'host' => '127.0.0.1',
            'port' => 6379,
            'password' => '',
            'database' => 0,
            'prefix' => 'kode:jwt:',
        ],
    ],
];
```

#### 3. 基础控制器

`app/base/AuthController.php`:

```php
<?php

declare(strict_types=1);

namespace app\base;

use think\App;
use think\Controller;
use Kode\Jwt\KodeJwt;

abstract class AuthController extends Controller
{
    protected ?object $jwtPayload = null;

    protected function initialize(): void
    {
        parent::initialize();
        
        $token = $this->request->header('Authorization');
        $token = $token ? str_replace('Bearer ', '', $token) : '';

        if (!$token) {
            $this->error('未提供 Token', [], 401);
        }

        try {
            $this->jwtPayload = KodeJwt::authenticate($token);
        } catch (\Exception $e) {
            $this->error($e->getMessage(), [], 401);
        }
    }

    protected function getUserId(): int|string
    {
        return $this->jwtPayload->uid;
    }

    protected function getUserPayload(): object
    {
        return $this->jwtPayload;
    }
}
```

#### 4. 控制器中使用

`app/controller/Auth.php`:

```php
<?php

declare(strict_types=1);

namespace app\controller;

use app\base\AuthController;
use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

class Auth extends AuthController
{
    public function login()
    {
        $credentials = $this->request->post();

        // 验证用户
        $user = \app\model\User::where('email', $credentials['email'] ?? '')->find();

        if (!$user || !password_verify($credentials['password'] ?? '', $user->password)) {
            $this->error('凭据无效');
        }

        $payload = Payload::create(
            uid: $user->id,
            username: $user->name,
            platform: 'web',
            exp: time() + 86400,
            iat: time(),
            jti: uniqid('jwt_'),
            roles: [$user->role],
        );

        $result = KodeJwt::issue($payload);

        return json([
            'token' => $result['token'],
            'expires_in' => $result['expires_in'],
        ]);
    }

    public function me()
    {
        return json([
            'id' => $this->getUserId(),
            'username' => $this->jwtPayload->username,
        ]);
    }

    public function refresh()
    {
        $token = $this->request->header('Authorization');
        $token = $token ? str_replace('Bearer ', '', $token) : '';

        $result = KodeJwt::refresh($token);

        return json([
            'token' => $result['token'],
            'expires_in' => $result['expires_in'],
        ]);
    }

    public function logout()
    {
        $token = $this->request->header('Authorization');
        $token = $token ? str_replace('Bearer ', '', $token) : '';

        KodeJwt::invalidate($token);

        return json(['message' => '已注销']);
    }
}
```

路由定义：

```php
// route/app.php
use app\controller\Auth;

Route::post('auth/login', [Auth::class, 'login']);
Route::group(function () {
    Route::get('auth/me', [Auth::class, 'me']);
    Route::post('auth/refresh', [Auth::class, 'refresh']);
    Route::post('auth/logout', [Auth::class, 'logout']);
})->middleware(\app\middleware\AuthMiddleware::class);
```

---

### 原生 PHP 集成

即使不使用框架，也可以轻松使用 kode/jwt：

```php
<?php

declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';

use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

// 初始化（使用默认配置或加载配置文件）
KodeJwt::detectAndLoadConfig();

// 或手动配置
KodeJwt::init([
    'defaults' => [
        'guard' => 'api',
        'storage' => 'memory',
    ],
    'guards' => [
        'api' => [
            'driver' => 'sso',
            'storage' => 'memory',
            'algo' => 'HS256',
            'secret' => file_get_contents(__DIR__ . '/storage/keys/secret'),
            'ttl' => 3600,
            'refresh_ttl' => 604800,
        ],
    ],
]);

// 生成 Token
$payload = Payload::create(
    uid: 'user_123',
    username: 'test_user',
    platform: 'web',
    exp: time() + 3600,
    iat: time(),
    jti: uniqid('jwt_'),
);

$result = KodeJwt::issue($payload);
$token = $result['token'];

echo "Token: {$token}\n";

// 验证 Token
try {
    $payload = KodeJwt::authenticate($token);
    echo "用户: {$payload->username}\n";
    echo "过期时间: " . date('Y-m-d H:i:s', $payload->exp) . "\n";
} catch (\Exception $e) {
    echo "验证失败: {$e->getMessage()}\n";
}

// 刷新 Token
$newResult = KodeJwt::refresh($token);
echo "新 Token: {$newResult['token']}\n";

// 注销 Token
KodeJwt::invalidate($token);
echo "已注销\n";
```

---

### Symfony 集成

#### 1. 安装配置

```bash
composer require kode/jwt
```

#### 2. 配置文件

`config/packages/jwt.yaml`:

```yaml
jwt:
    defaults:
        guard: api
        storage: redis
    guards:
        api:
            driver: sso
            storage: redis
            algo: RS256
            public_key: '%kernel.project_dir%/var/keys/public.pem'
            private_key: '%kernel.project_dir%/var/keys/private.pem'
            ttl: 3600
            refresh_ttl: 604800
    storage:
        redis:
            host: 127.0.0.1
            port: 6379
            prefix: 'kode:jwt:'
```

#### 3. 服务配置

`config/services.yaml`:

```yaml
services:
    Kode\Jwt\KodeJwt:
        class: Kode\Jwt\KodeJwt
        calls:
            - method: detectAndLoadConfig

    App\Security\JwtAuthenticator:
        arguments:
            $jwtService: '@Kode\Jwt\KodeJwt'
```

#### 4. 自定义认证器

`src/Security/JwtAuthenticator.php`:

```php
<?php

namespace App\Security;

use Kode\Jwt\KodeJwt;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

class JwtAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private KodeJwt $jwtService
    ) {}

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization');
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        $token = $request->headers->get('Authorization');
        $token = str_replace('Bearer ', '', $token);

        $payload = $this->jwtService->authenticate($token);

        return new SelfValidatingPassport(
            new UserBadge($payload->uid, function () use ($payload) {
                return new User($payload->uid, [], [], $payload->roles ?? []);
            })
        );
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new JsonResponse(['error' => '认证失败'], 401);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }
}
```

---

### Yii2 集成

#### 1. 安装配置

```bash
composer require kode/jwt
```

#### 2. 配置文件

`config/main.php`:

```php
<?php

return [
    'components' => [
        'jwt' => [
            'class' => 'Kode\Jwt\KodeJwt',
            'config' => [
                'defaults' => [
                    'guard' => 'api',
                    'provider' => 'user',
                    'platform' => 'web',
                ],
                'guards' => [
                    'api' => [
                        'driver' => 'sso',
                        'provider' => 'user',
                        'storage' => 'redis',
                        'blacklist_enabled' => true,
                        'refresh_enabled' => true,
                        'refresh_ttl' => 20160,
                        'ttl' => 1440,
                        'algo' => 'RS256',
                        'public_key' => '@app/runtime/keys/public.pem',
                        'private_key' => '@app/runtime/keys/private.pem',
                    ],
                ],
                'storage' => [
                    'redis' => [
                        'connection' => 'default',
                        'prefix' => 'kode:jwt:',
                    ],
                ],
            ],
        ],
    ],
];
```

#### 3. 生成密钥脚本

`commands/JwtController.php`:

```php
<?php

namespace app\commands;

use Yii;
use yii\console\Controller;
use Kode\Jwt\KodeJwt;

class JwtController extends Controller
{
    public function actionInit()
    {
        $keyDir = Yii::getAlias('@app/runtime/keys');
        
        if (!is_dir($keyDir)) {
            mkdir($keyDir, 0755, true);
        }
        
        KodeJwt::init([
            'defaults' => [
                'guard' => 'api',
            ],
            'guards' => [
                'api' => [
                    'driver' => 'sso',
                    'storage' => 'redis',
                    'algo' => 'RS256',
                    'public_key' => $keyDir . '/public.pem',
                    'private_key' => $keyDir . '/private.pem',
                    'ttl' => 1440,
                    'refresh_ttl' => 20160,
                ],
            ],
        ]);
        
        $result = KodeJwt::generateKeys('rsa', $keyDir);
        
        if ($result['success']) {
            echo "✅ 密钥生成成功！\n";
            echo "私钥: {$result['private_key_path']}\n";
            echo "公钥: {$result['public_key_path']}\n";
        } else {
            echo "❌ 密钥生成失败: {$result['error']}\n";
        }
    }
}
```

运行命令：

```bash
php yii jwt/init
```

#### 4. 行为类实现

`components/AuthenticatedBehavior.php`:

```php
<?php

namespace app\components;

use Yii;
use yii\base\Behavior;
use yii\web\Controller;
use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

class AuthenticatedBehavior extends Behavior
{
    public function events()
    {
        return [
            Controller::EVENT_BEFORE_ACTION => 'beforeAction',
        ];
    }

    public function beforeAction($action)
    {
        $request = Yii::$app->request;
        $authHeader = $request->getHeaders()->get('Authorization');
        
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            Yii::$app->response->statusCode = 401;
            echo json_encode(['error' => '未提供认证令牌']);
            return false;
        }
        
        $token = substr($authHeader, 7);
        
        try {
            $payload = KodeJwt::authenticate($token);
            
            Yii::$app->user->identity = $this->findUser($payload->uid);
            Yii::$app->jwtPayload = $payload;
            
            return true;
        } catch (\Exception $e) {
            Yii::$app->response->statusCode = 401;
            echo json_encode(['error' => '认证失败: ' . $e->getMessage()]);
            return false;
        }
    }
    
    protected function findUser($uid)
    {
        return \app\models\User::findOne($uid);
    }
}
```

#### 5. 控制器使用示例

`controllers/ApiController.php`:

```php
<?php

namespace app\controllers;

use Yii;
use yii\rest\Controller;
use app\components\AuthenticatedBehavior;
use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

class ApiController extends Controller
{
    public function behaviors()
    {
        $behaviors = parent::behaviors();
        $behaviors['auth'] = AuthenticatedBehavior::class;
        return $behaviors;
    }
    
    public function actionLogin()
    {
        $request = Yii::$app->request;
        $username = $request->post('username');
        $password = $request->post('password');
        
        $user = \app\models\User::findOne(['username' => $username]);
        
        if (!$user || !$user->validatePassword($password)) {
            throw new \yii\web\UnauthorizedHttpException('用户名或密码错误');
        }
        
        $payload = Payload::create(
            uid: $user->id,
            username: $user->username,
            platform: 'web',
            exp: time() + 1440 * 60,
            iat: time(),
            jti: uniqid('jwt_'),
            roles: [$user->role],
        );
        
        $result = KodeJwt::issue($payload);
        
        return [
            'token' => $result['token'],
            'expires_in' => $result['expires_in'],
            'refresh_ttl' => $result['refresh_ttl'],
        ];
    }
    
    public function actionProfile()
    {
        $payload = Yii::$app->jwtPayload;
        
        return [
            'uid' => $payload->uid,
            'username' => $payload->username,
            'roles' => $payload->roles,
        ];
    }
    
    public function actionRefresh()
    {
        $request = Yii::$app->request;
        $refreshToken = $request->post('refresh_token');
        
        $result = KodeJwt::refresh($refreshToken);
        
        return [
            'token' => $result['token'],
            'expires_in' => $result['expires_in'],
        ];
    }
    
    public function actionLogout()
    {
        $request = Yii::$app->request;
        $token = $request->post('token');
        
        KodeJwt::invalidate($token);
        
        return ['message' => '已成功注销'];
    }
}
```

---

### CakePHP 集成

#### 1. 安装配置

```bash
composer require kode/jwt
```

#### 2. 配置文件

`config/jwt.php`:

```php
<?php

return [
    'Jwt' => [
        'defaults' => [
            'guard' => 'api',
            'provider' => 'Users',
            'platform' => 'web',
        ],
        'guards' => [
            'api' => [
                'driver' => 'sso',
                'provider' => 'Users',
                'storage' => 'redis',
                'blacklist_enabled' => true,
                'refresh_enabled' => true,
                'refresh_ttl' => 20160,
                'ttl' => 1440,
                'algo' => 'RS256',
                'public_key' => ROOT . '/config/keys/public.pem',
                'private_key' => ROOT . '/config/keys/private.pem',
            ],
        ],
        'storage' => [
            'redis' => [
                'connection' => 'default',
                'prefix' => 'kode:jwt:',
            ],
        ],
    ],
];
```

在 `config/bootstrap.php` 中加载配置：

```php
use Kode\Jwt\KodeJwt;

$jwtConfig = require ROOT . '/config/jwt.php';
KodeJwt::init($jwtConfig['Jwt']);
```

#### 3. Shell 任务生成密钥

`src/Shell/JwtShell.php`:

```php
<?php

namespace App\Shell;

use Cake\Console\Shell;
use Kode\Jwt\KodeJwt;

class JwtShell extends Shell
{
    public function main()
    {
        $keyDir = ROOT . '/config/keys';
        
        if (!is_dir($keyDir)) {
            mkdir($keyDir, 0755, true);
        }
        
        $this->out('正在生成 RSA 密钥对...');
        
        $result = KodeJwt::generateKeys('rsa', $keyDir);
        
        if ($result['success']) {
            $this->out('<success>✅ 密钥生成成功！</success>');
            $this->out("私钥: {$result['private_key_path']}");
            $this->out("公钥: {$result['public_key_path']}");
        } else {
            $this->out('<error>❌ 密钥生成失败: ' . $result['error'] . '</error>');
        }
    }
}
```

运行命令：

```bash
bin/cake jwt
```

#### 4. 中间件实现

`src/Middleware/JwtAuthenticationMiddleware.php`:

```php
<?php

namespace App\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

class JwtAuthenticationMiddleware
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $authHeader = $request->getHeaderLine('Authorization');
        
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return $this->unauthorizedResponse('未提供认证令牌');
        }
        
        $token = substr($authHeader, 7);
        
        try {
            $payload = KodeJwt::authenticate($token);
            
            $request = $request->withAttribute('jwt_payload', $payload);
            $request = $request->withAttribute('user_id', $payload->uid);
            
            return $handler->handle($request);
        } catch (\Exception $e) {
            return $this->unauthorizedResponse('认证失败: ' . $e->getMessage());
        }
    }
    
    protected function unauthorizedResponse(string $message): ResponseInterface
    {
        return new \ Laminas\Diactoros\Response\JsonResponse([
            'error' => $message,
        ], 401);
    }
}
```

在 `src/Application.php` 中注册中间件：

```php
public function middleware(MiddlewareQueue $middlewareQueue): MiddlewareQueue
{
    $middlewareQueue->add(new \App\Middleware\JwtAuthenticationMiddleware());
    
    return $middlewareQueue;
}
```

#### 5. 控制器使用示例

`src/Controller/AuthController.php`:

```php
<?php

namespace App\Controller;

use Cake\Controller\Controller;
use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

class AuthController extends Controller
{
    public function login()
    {
        $username = $this->request->getData('username');
        $password = $this->request->getData('password');
        
        $user = $this->Users->findByUsername($username)->first();
        
        if (!$user || !$user->verifyPassword($password)) {
            $this->response = $this->response->withStatus(401);
            $this->set(['error' => '用户名或密码错误']);
            $this->set('_serialize', ['error']);
            return;
        }
        
        $payload = Payload::create(
            uid: $user->id,
            username: $user->username,
            platform: 'web',
            exp: time() + 1440 * 60,
            iat: time(),
            jti: uniqid('jwt_'),
            roles: [$user->role],
        );
        
        $result = KodeJwt::issue($payload);
        
        $this->set([
            'token' => $result['token'],
            'expires_in' => $result['expires_in'],
            'refresh_ttl' => $result['refresh_ttl'],
        ]);
        $this->set('_serialize', ['token', 'expires_in', 'refresh_ttl']);
    }
    
    public function profile()
    {
        $payload = $this->request->getAttribute('jwt_payload');
        
        $this->set([
            'uid' => $payload->uid,
            'username' => $payload->username,
            'roles' => $payload->roles,
        ]);
        $this->set('_serialize', ['uid', 'username', 'roles']);
    }
    
    public function refresh()
    {
        $refreshToken = $this->request->getData('refresh_token');
        
        $result = KodeJwt::refresh($refreshToken);
        
        $this->set([
            'token' => $result['token'],
            'expires_in' => $result['expires_in'],
        ]);
        $this->set('_serialize', ['token', 'expires_in']);
    }
    
    public function logout()
    {
        $token = $this->request->getData('token');
        
        KodeJwt::invalidate($token);
        
        $this->set(['message' => '已成功注销']);
        $this->set('_serialize', ['message']);
    }
}
```

#### 6. 组件封装

`src/Controller/Component/JwtComponent.php`:

```php
<?php

namespace App\Controller\Component;

use Cake\Controller\Component;
use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

class JwtComponent extends Component
{
    protected $_defaultConfig = [
        'guard' => 'api',
    ];
    
    public function initialize(array $config): void
    {
        parent::initialize($config);
        
        KodeJwt::detectAndLoadConfig();
    }
    
    public function issue(array $userData, string $platform = 'web'): array
    {
        $payload = Payload::create(
            uid: $userData['id'],
            username: $userData['username'] ?? null,
            platform: $platform,
            exp: time() + 1440 * 60,
            iat: time(),
            jti: uniqid('jwt_'),
            roles: $userData['roles'] ?? null,
            perms: $userData['perms'] ?? null,
        );
        
        return KodeJwt::issue($payload);
    }
    
    public function authenticate(string $token): Payload
    {
        return KodeJwt::authenticate($token);
    }
    
    public function refresh(string $token): array
    {
        return KodeJwt::refresh($token);
    }
    
    public function invalidate(string $token): void
    {
        KodeJwt::invalidate($token);
    }
    
    public function getPayload(): ?Payload
    {
        return $this->getController()->request->getAttribute('jwt_payload');
    }
    
    public function getUserId(): mixed
    {
        $payload = $this->getPayload();
        return $payload?->uid;
    }
    
    public function hasRole(string $role): bool
    {
        $payload = $this->getPayload();
        return $payload && in_array($role, $payload->roles ?? []);
    }
    
    public function hasPermission(string $permission): bool
    {
        $payload = $this->getPayload();
        return $payload && in_array($permission, $payload->perms ?? []);
    }
}
```

在控制器中使用组件：

```php
<?php

namespace App\Controller;

class ApiController extends Controller
{
    public function initialize(): void
    {
        parent::initialize();
        $this->loadComponent('Jwt');
    }
    
    public function protectedAction()
    {
        $userId = $this->Jwt->getUserId();
        $hasAdminRole = $this->Jwt->hasRole('admin');
        
        $this->set(compact('userId', 'hasAdminRole'));
    }
}
```

---

### 使用 CLI独立 工具

即使不通过 Composer 安装，也可以使用 CLI 工具：

```bash
# 下载并解压包后
php bin/jwt install --config-only
php bin/jwt key rsa --force
```

---

## 📖 API 参考

### KodeJwt 门面类

`KodeJwt` 是包的主入口点，提供静态方法访问所有功能。

#### 初始化与配置

```php
// 方式1：自动检测并加载配置文件
KodeJwt::detectAndLoadConfig();

// 方式2：手动初始化（使用默认配置）
KodeJwt::init();

// 方式3：手动初始化（使用自定义配置）
KodeJwt::init([
    'defaults' => [
        'guard' => 'api',
        'platform' => 'web',
    ],
    'guards' => [
        'api' => [
            'driver' => 'sso',
            'storage' => 'redis',
            'algo' => 'RS256',
            'ttl' => 1440,
        ],
    ],
]);

// 方式4：从文件加载配置
KodeJwt::loadConfigFromFile('/path/to/config/jwt.php');
```

#### 获取守卫实例

```php
// 获取默认守卫
$guard = KodeJwt::guard();

// 获取指定守卫
$guard = KodeJwt::guard('api');

// 获取默认守卫（别名）
$guard = KodeJwt::guard('default');
```

#### Token 操作方法

```php
// 签发 Token
$result = KodeJwt::issue(Payload $payload): array;
// 返回: ['token' => string, 'expires_in' => int, 'refresh_ttl' => int]

// 验证 Token 并返回 Payload
$payload = KodeJwt::authenticate(string $token): Payload;

// 刷新 Token
$result = KodeJwt::refresh(string $token): array;
// 返回: ['token' => string, 'expires_in' => int]

// 注销 Token（加入黑名单）
KodeJwt::invalidate(string $token): void;

// 检查 Token 是否有效
$isValid = KodeJwt::isTokenValid(string $token): bool;

// 获取 Token 详细信息
$info = KodeJwt::getTokenInfo(string $token): array;
// 返回: ['uid' => int|string, 'platform' => string, 'exp' => int, ...]
```

#### 用户 Token 管理

```php
// 获取用户的所有活跃 Token
$tokens = KodeJwt::getUserTokens(int|string $uid, string $platform): array;

// 强制注销用户的所有 Token
$count = KodeJwt::revokeUserTokens(int|string $uid, string $platform): int;
```

#### 存储操作

```php
// 清理过期的 Token
$count = KodeJwt::cleanExpired(): int;

// 获取存储统计信息
$stats = KodeJwt::getStats(): array;
// 返回: ['total' => int, 'expired' => int, 'active' => int]
```

#### 密钥生成

```php
// 生成密钥对
$result = KodeJwt::generateKeys(string $type, ?string $path = null): array;
// $type: 'rsa' | 'hmac'
// 返回: ['success' => bool, 'private_key_path' => string, 'public_key_path' => string, 'error' => string]

// 示例
$result = KodeJwt::generateKeys('rsa', '/path/to/keys');
if ($result['success']) {
    echo "私钥: {$result['private_key_path']}";
    echo "公钥: {$result['public_key_path']}";
}
```

#### 事件系统

```php
// 获取事件调度器实例
$events = KodeJwt::events(): EventDispatcher;

// 监听事件
KodeJwt::events()->on(TokenIssued::class, function ($event) {
    // $event->payload
});

// 移除监听器
KodeJwt::events()->off(TokenIssued::class);
```

---

### Payload 类

`Payload` 类用于构建和管理 JWT Payload。

#### 创建 Payload

```php
// 方式1：使用构造函数
$payload = new Payload(
    uid: 123,
    username: 'john_doe',
    platform: 'web',
    exp: time() + 3600,
    iat: time(),
    jti: uniqid('jwt_'),
    roles: ['user'],
    perms: ['read', 'write'],
    custom: ['department' => 'IT']
);

// 方式2：使用静态方法 create()
$payload = Payload::create(
    uid: 123,
    username: 'john_doe',
    platform: 'web',
    exp: time() + 3600,
    iat: time(),
    jti: uniqid('jwt_'),
    roles: ['user'],
    perms: ['read', 'write'],
    customData: ['department' => 'IT']
);

// 方式3：从数组创建
$payload = Payload::fromArray([
    'uid' => 123,
    'username' => 'john_doe',
    'platform' => 'web',
    'exp' => time() + 3600,
    'iat' => time(),
    'jti' => uniqid('jwt_'),
    'roles' => ['user'],
    'perms' => ['read', 'write'],
    'custom' => ['department' => 'IT'],
]);
```

#### Payload 属性

| 属性 | 类型 | 说明 |
|------|------|------|
| `uid` | `int\|string\|null` | 用户 ID |
| `username` | `string\|null` | 用户名 |
| `platform` | `string` | 平台标识 |
| `exp` | `int` | 过期时间戳 |
| `iat` | `int` | 签发时间戳 |
| `jti` | `string` | JWT ID（唯一标识） |
| `roles` | `array\|null` | 用户角色 |
| `perms` | `array\|null` | 用户权限 |
| `custom` | `array` | 自定义数据 |

#### Payload 方法

```php
// 转换为数组
$array = $payload->toArray(): array;

// 获取自定义数据
$custom = $payload->getCustomData(): array;

// 获取特定自定义数据
$value = $payload->getCustom(string $key, mixed $default = null): mixed;

// 检查自定义数据是否存在
$exists = $payload->hasCustom(string $key): bool;

// 检查是否具有角色
$hasRole = $payload->hasRole(string $role): bool;

// 检查是否具有权限
$hasPerm = $payload->hasPermission(string $permission): bool;

// 获取用户信息
$userInfo = $payload->getUserInfo(): array;

// 检查是否已过期
$isExpired = $payload->isExpired(): bool;

// 获取剩余有效时间（秒）
$ttl = $payload->getTtl(): int;

// 获取用户标识
$userId = $payload->getUserIdentifier(): mixed;
```

---

### Guard 接口

```php
use Kode\Jwt\Contract\GuardInterface;

interface GuardInterface
{
    // 签发 Token
    public function issue(Payload $payload): array;

    // 验证 Token
    public function authenticate(string $token): Payload;

    // 刷新 Token
    public function refresh(string $token): array;

    // 注销 Token
    public function invalidate(string $token): void;

    // 检查 Token 是否有效
    public function isValid(string $token): bool;

    // 获取 Token 信息
    public function getTokenInfo(string $token): array;
}
```

---

### Storage 接口

```php
use Kode\Jwt\Contract\StorageInterface;

interface StorageInterface
{
    // 设置缓存
    public function set(string $key, mixed $value, int $ttl = 0): bool;

    // 获取缓存
    public function get(string $key, mixed $default = null): mixed;

    // 删除缓存
    public function delete(string $key): bool;

    // 检查键是否存在
    public function has(string $key): bool;

    // 加入黑名单
    public function blacklist(string $jti, int $ttl = 3600): bool;

    // 检查是否在黑名单中
    public function isBlacklisted(string $jti): bool;

    // 批量设置
    public function setMultiple(array $values, int $ttl = 0): bool;

    // 批量获取
    public function getMultiple(array $keys, mixed $default = null): array;

    // 批量删除
    public function deleteMultiple(array $keys): bool;

    // 清空所有缓存
    public function flush(): bool;

    // 获取存储统计信息
    public function stats(): array;
}
```

---

### 事件类

#### TokenIssued

```php
use Kode\Jwt\Event\TokenIssued;

$event = new TokenIssued(Payload $payload);

// 访问 Payload
$uid = $event->payload->uid;
$jti = $event->payload->jti;
```

#### TokenExpired

```php
use Kode\Jwt\Event\TokenExpired;

$event = new TokenExpired(Payload $payload);
```

#### TokenRevoked

```php
use Kode\Jwt\Event\TokenRevoked;

$event = new TokenRevoked(Payload $payload);
```

---

### 异常类

```php
use Kode\Jwt\Exception\TokenInvalidException;
use Kode\Jwt\Exception\TokenExpiredException;
use Kode\Jwt\Exception\TokenBlacklistedException;

// Token 无效
throw new TokenInvalidException(string $message = '');

// Token 已过期
throw new TokenExpiredException(string $message = '');

// Token 在黑名单中
throw new TokenBlacklistedException(string $message = '');
```

---

## 📚 最佳实践

### 1. 密钥管理

```php
// 推荐：使用环境变量
$secret = getenv('JWT_SECRET') ?: $_ENV['JWT_SECRET'];

// 或从文件加载
$privateKey = file_get_contents(storage_path('keys/private.pem'));
$publicKey = file_get_contents(storage_path('keys/public.pem'));

// 配置
KodeJwt::init([
    'guards' => [
        'api' => [
            'algo' => 'RS256',
            'private_key' => $privateKey,
            'public_key' => $publicKey,
        ],
    ],
]);
```

### 2. 多守卫配置

```php
return [
    'defaults' => [
        'guard' => 'api',
    ],

    'guards' => [
        'api' => [
            'driver' => 'sso',
            'storage' => 'redis',
            'algo' => 'RS256',
            'ttl' => 3600,
            'platform' => null,
        ],
        'admin' => [
            'driver' => 'sso',
            'storage' => 'redis',
            'algo' => 'RS256',
            'ttl' => 1800, // 管理员 Token 更短
            'platform' => 'admin',
        ],
        'mobile' => [
            'driver' => 'mlo', // 多点登录
            'storage' => 'redis',
            'algo' => 'HS256',
            'ttl' => 86400,
            'max_devices' => 3,
        ],
    ],
];
```

### 3. 事件监听

```php
use Kode\Jwt\KodeJwt;

// Token 签发事件
KodeJwt::events()->on(\Kode\Jwt\Event\TokenIssued::class, function ($event) {
    error_log("Token 签发: uid={$event->payload->uid}, jti={$event->payload->jti}");
});

// Token 注销事件
KodeJwt::events()->on(\Kode\Jwt\Event\TokenRevoked::class, function ($event) {
    error_log("Token 注销: uid={$event->payload->uid}");
});
```

### 4. 错误处理

```php
use Kode\Jwt\Exception\TokenInvalidException;
use Kode\Jwt\Exception\TokenExpiredException;
use Kode\Jwt\Exception\TokenBlacklistedException;

try {
    $payload = KodeJwt::authenticate($token);
} catch (TokenInvalidException $e) {
    // Token 无效（签名错误）
    return response()->json(['error' => 'Token 无效'], 401);
} catch (TokenExpiredException $e) {
    // Token 已过期
    return response()->json(['error' => 'Token 已过期，请刷新'], 401);
} catch (TokenBlacklistedException $e) {
    // Token 已被加入黑名单
    return response()->json(['error' => 'Token 已被注销'], 401);
} catch (\Exception $e) {
    // 其他错误
    return response()->json(['error' => '认证失败'], 500);
}
```

---

## 🔧 扩展指南

### 自定义存储驱动

```php
namespace App\Storage;

use Kode\Jwt\Contract\StorageInterface;

class CustomStorage implements StorageInterface
{
    public function set(string $key, mixed $value, int $ttl = 0): bool
    {
        // 实现逻辑
    }

    public function get(string $key, mixed $default = null): mixed
    {
        // 实现逻辑
    }

    public function delete(string $key): bool
    {
        // 实现逻辑
    }

    public function has(string $key): bool
    {
        // 实现逻辑
    }

    public function cleanExpired(): int
    {
        // 实现逻辑
    }

    public function getStats(): array
    {
        // 实现逻辑
    }
}
```

注册自定义驱动：

```php
KodeJwt::init([
    'guards' => [
        'api' => [
            'driver' => 'sso',
            'storage' => 'custom', // 使用自定义存储
        ],
    ],
    'storage' => [
        'custom' => [
            'driver' => \App\Storage\CustomStorage::class,
        ],
    ],
]);
```

### 自定义守卫

```php
namespace App\Guard;

use Kode\Jwt\Contract\GuardInterface;
use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Token\Payload;

class CustomGuard implements GuardInterface
{
    public function __construct(
        private StorageInterface $storage,
        private array $config
    ) {}

    public function issue(Payload $payload): array
    {
        // 自定义签发逻辑
    }

    public function authenticate(string $token): Payload
    {
        // 自定义验证逻辑
    }

    public function refresh(string $token): array
    {
        // 自定义刷新逻辑
    }

    public function invalidate(string $token): bool
    {
        // 自定义注销逻辑
    }

    public function validateToken(string $token): bool
    {
        // 自定义验证逻辑
    }
}
```

---

## 📦 依赖与兼容性

### 必需依赖

- PHP >= 8.1
- ext-json
- ext-openssl

### 可选依赖

- ext-redis：Redis 存储驱动
- ext-pdo：数据库存储驱动
- ext-swoole：Swoole 协程支持

### 兼容环境

- PHP-FPM
- Swoole
- RoadRunner
- ReactPHP
- Amp

---