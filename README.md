# Kode JWT：一个健壮、全面、现代化的 PHP 8.3+ JWT 包

> **项目名称**：`kode/jwt`  
> **当前版本**：`v1.11.1`  
> **目标**：为现代 PHP 应用提供安全、灵活、高性能的 JWT 身份验证解决方案，支持单点登录（SSO）、多点登录、黑名单管理、自动续期、多平台适配、防重放攻击（Anti-Replay）、JWK 密钥管理、Token 客户端指纹绑定、JWKS 端点发布、Token Introspection、OIDC Discovery，兼容 FPM、Swoole、RoadRunner 等运行环境。

---

## 📌 项目愿景

构建一个**生产级、零侵入、高可扩展**的 JWT 包，专为 PHP 8.3+ 设计，充分利用现代 PHP 特性（`readonly class`、类型化类常量、`json_validate()`、`#[\Override]` 属性、`enum`、联合类型、反射优化），并支持主流框架（Laravel、Symfony、ThinkPHP、Hyperf、EasySwoole 等）无缝接入。
可使用 kode 相关包或其他通用适合的包快速集成。

---

## 🚀 核心特性

| 特性 | 说明 |
|------|------|
| ✅ **PHP 8.3+ 原生支持** | 使用 `readonly class`、类型化类常量（`private const array FOO = [...]`）、`json_validate()`、`#[\Override]` 属性等 PHP 8.3+ 特性 |
| ✅ **多平台支持** | H5、PC、App、小程序（微信/支付宝/抖音）等，通过 `platform` 声明区分，是否启用平台，平台配置一致或单独配置 |
| ✅ **单点登录（SSO）** | 同一用户在同一平台仅允许一个有效 Token，支持 Redis Lua 原子化踢出 |
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
| ✅ **防重放攻击（Anti-Replay）** | 基于 Redis Nonce + 滑动窗口，杜绝 Token 被截获后重复使用 |
| ✅ **高熵 JTI** | 32 字节（256 bit）密码学安全随机数，远高于 UUID v4 |
| ✅ **标准声明（iss/aud/sub）** | 业务级强制校验，防止跨服务/跨租户混用 |
| ✅ **时钟漂移容忍** | 跨节点 NTP 偏差场景下，配置 `clock_skew` 即可容错 |
| ✅ **Redis 原子化撤销** | Lua 脚本保证"黑名单 + SSO 映射 + 用户 Token 列表"三步原子性 |
| 🆕 v1.9 **JWK 密钥管理（RFC 7517）** | `Jwk` / `JwkSet` / `KeyConverter` / `JwkFactory`，支持 RSA / EC / oct 三种密钥类型，PEM ↔ JWK 互转，CSPRNG 安全密钥生成 |
| 🆕 v1.9 **Token 客户端指纹绑定** | `Fingerprint` 组件将 Token 与客户端 UA + IP 前缀绑定，防止跨设备重放，内置可信内网 IP 白名单 |
| 🆕 v1.9 **算法白名单强制校验** | 三层防御：永久禁用 `none` 算法 → 显式白名单 → 单算法严格匹配，杜绝算法混淆攻击 |
| 🆕 v1.9 **PHP 8.3 readonly class** | `Jwk`、`JwkSet` 等核心值对象使用 `final readonly class`，运行期不可变，防止密钥被篡改 |
| 🆕 v1.9 **类型化类常量** | 使用 `private const array SUPPORTED_KTY = [...]` 等 PHP 8.3 类型化常量，强化类型安全 |
| 🆕 v1.10 **JWKS 端点发布（RFC 7517 §5）** | `JwksPublisher` 将 JWK Set 以标准 JSON 格式发布到 `jwks_uri`，自动剥离私钥，支持 ETag / If-None-Match 协商缓存 |
| 🆕 v1.10 **Token Introspection（RFC 7662）** | `Introspector` + `IntrospectionResponse` 提供标准 introspection 端点，资源服务器可查询 Token 当前状态 |
| 🆕 v1.10 **OIDC Discovery（RFC 8414）** | `DiscoveryConfiguration` + `DiscoveryPublisher` 发布授权服务器元数据，支持 `/.well-known/openid-configuration` |
| 🆕 v1.10 **Scope 值对象与声明检查器** | `Scope` 不可变集合（has/hasAny/hasAll/intersect/diff），`ClaimInspector` 链式校验 issuer/audience/scope/time window |
| 🆕 v1.10 **TokenPolicy 策略对象** | 不可变策略值对象，链式配置（issuer/audience/platform/scope/custom），一次性 `enforce()` 完成 Token 校验 |
| 🆕 v1.11 **完整 JWS 算法族（RFC 7518/8017/8037）** | `Signer` 统一门面：HMAC + RSA-PSS（真 EMSA-PSS）+ ECDSA（R‖S 标准 raw）+ EdDSA（Ed25519） |
| 🆕 v1.11 **cnf 确认声明（RFC 7800）** | `Confirmation` 值对象，支持 jkt/jwk/jku/kid，绑定密钥指纹 |
| 🆕 v1.11 **DPoP 持有证明（RFC 9449）** | `DPoPProofBuilder` / `DPoPValidator`：内联公钥 JWK 证明，防 Token 重放/转发 |
| 🆕 v1.11 **Token 撤销端点（RFC 7009）** | `RevocationHandler` 将 jti 加入黑名单，被撤销 Token 立即失效 |
| 🆕 v1.11 **JWK 指纹（RFC 7638）** | `Jwk::thumbprint()` 跨语言一致指纹，支持 RSA/EC/OKP/oct；EC/OKP PEM↔JWK 互转 |

---

## 📁 项目结构（PSR-4）

```bash
src/
├── Contract/           # 所有接口定义
│   ├── TokenManagerInterface.php
│   ├── StorageInterface.php
│   ├── GuardInterface.php
│   ├── SsoStorageInterface.php     # SSO 高级能力（atomicRevoke/trackUserToken/...）
│   ├── ReplayProtectionInterface.php
│   ├── EventInterface.php
│   ├── EventListener.php
│   ├── Arrayable.php
│   ├── Jsonable.php
│   └── LoggerInterface.php
├── Token/              # Token 核心类
│   ├── Builder.php                  # 签发构造器（含公私钥 mtime 缓存）
│   ├── Parser.php                   # 解析校验器（含算法白名单三层防御）
│   ├── Claim.php
│   ├── Payload.php                  # readonly 值对象
│   └── TokenManager.php
├── Guard/              # 守卫机制
│   ├── BaseGuard.php                # 支持 ttl_unit / refresh_ttl_unit 配置
│   ├── SsoGuard.php
│   └── MloGuard.php
├── Storage/            # 存储驱动
│   ├── RedisStorage.php             # + SsoStorageInterface (Lua 原子撤销)
│   ├── CoroutineRedisStorage.php    # Swoole 协程 Redis
│   ├── MemoryStorage.php
│   ├── FileStorage.php              # sha256 短哈希防 key 碰撞
│   ├── ApcuStorage.php
│   ├── DatabaseStorage.php          # MySQL/SQLite 方言自动适配
│   ├── MemcachedStorage.php
│   ├── NullStorage.php
│   ├── RedisReplayProtection.php
│   └── StorageFactory.php
├── Key/                # 🆕 v1.9 JWK 密钥管理（RFC 7517）
│   ├── Jwk.php                      # final readonly class 值对象
│   ├── JwkSet.php                   # JWK 集合（密钥轮换）
│   ├── KeyConverter.php             # PEM ↔ JWK 互转（ASN.1 DER 编码）
│   └── JwkFactory.php               # CSPRNG 安全密钥生成
├── KeyRotation/        # 密钥轮换
│   ├── KeyRotationManager.php       # getMultiple 批量优化
│   └── KeyVersion.php
├── Security/           # 安全组件
│   ├── AntiReplay.php               # Nonce 一次性消费 + 滑动窗口
│   └── Fingerprint.php              # 🆕 v1.9 客户端指纹绑定（UA + IP 前缀）
├── Signature/          # 多签机制
│   ├── MultiSignature.php
│   └── SignatureResult.php
├── Event/              # 事件系统
│   ├── BaseEvent.php
│   ├── EventDispatcher.php
│   ├── EventServiceProvider.php
│   ├── TokenIssued.php
│   ├── TokenExpired.php
│   ├── TokenRefreshed.php
│   ├── TokenRevoked.php
│   ├── TokenBlacklisted.php
│   └── TokenValidated.php
├── Exception/          # 自定义异常
│   ├── JwtException.php
│   ├── TokenInvalidException.php
│   ├── TokenExpiredException.php
│   ├── TokenBlacklistedException.php
│   └── TokenReplayException.php
├── Config/             # 配置管理
│   └── ConfigLoader.php
├── Enum/               # 枚举
│   ├── Algorithm.php
│   ├── GuardMode.php
│   └── StorageType.php
├── Log/                # 日志适配
│   ├── FileLogger.php
│   ├── NullLogger.php
│   ├── MonologAdapter.php
│   └── LoggerFactory.php
├── Metrics/            # 监控指标
│   └── PrometheusMetrics.php
├── OAuth2/             # OAuth2 模块
│   ├── HybridProvider.php
│   ├── HybridTokenResponse.php
│   ├── JwksPublisher.php            # 🆕 v1.10 JWKS 端点发布器
│   ├── JwksResponse.php             # 🆕 v1.10 JWKS 响应值对象
│   ├── IntrospectionResponse.php    # 🆕 v1.10 RFC 7662 内省响应
│   └── Introspector.php             # 🆕 v1.10 RFC 7662 内省服务
├── OpenId/             # OpenID Connect
│   ├── IdTokenBuilder.php
│   ├── UserInfo.php
│   ├── DiscoveryConfiguration.php   # 🆕 v1.10 RFC 8414 Discovery 元数据
│   └── DiscoveryPublisher.php       # 🆕 v1.10 Discovery 端点发布器
├── Claim/              # 🆕 v1.10 声明模块
│   ├── Scope.php                    # OAuth2/OIDC Scope 值对象
│   └── ClaimInspector.php           # 链式声明校验器
├── Policy/             # 🆕 v1.10 策略模块
│   └── TokenPolicy.php              # Token 校验策略值对象
├── Support/            # 辅助工具
│   ├── ImmutableDto.php
│   └── PhpFeature.php
├── Console/            # CLI 命令
│   ├── InstallCommand.php
│   ├── KeyGenerateCommand.php
│   └── TokenCommand.php
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
```

> ⚠️ **`KodeJwt::builder()` 不可跨请求共享（Builder 是可变对象）**
> `KodeJwt::builder()` 每次调用都返回**全新实例**，因此以下两种用法都是安全的：
> ```php
> // ✅ 推荐：每次需要都重新获取，状态天然隔离
> $token = KodeJwt::builder()->setUid(123)->issue();
>
> // ✅ 有意复用同一个实例时，先 reset() 清空前次累积的 claims / jti
> $builder = KodeJwt::builder();
> $builder->setUid(123)->issue();
> $builder->reset();              // 必须：否则会泄漏上次的 claims、碰撞 jti
> $builder->setUid(456)->issue();
> ```
> 切勿把 `KodeJwt::builder()` 的返回值存为全局/静态单例并在多次签发间复用，否则会出现 claims 泄漏与前次 jti 碰撞。
> 生产环境签发更推荐 `KodeJwt::guard($g)->issue(new Payload(...))`，由 Guard 内部管理独立实例。

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

## 🚀 快速开始（v1.10.x）

### 1. 最小化示例

```php
<?php
require 'vendor/autoload.php';

use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

// 1. 初始化（使用内存存储，演示用）
KodeJwt::init([
    'guards' => [
        'api' => [
            'driver' => 'sso',
            'storage' => 'memory',
            'secret' => 'your-256-bit-secret-key',
        ],
    ],
]);

// 2. 签发 Token
$now = time();
$payload = Payload::create(
    uid: 1001,
    username: 'alice',
    platform: 'web',
    exp: $now + 3600,
    iat: $now,
    jti: Payload::generateJti(),    // 高熵 JTI
);
$token = KodeJwt::issue($payload)['token'];

// 3. 验证 Token
$verified = KodeJwt::authenticate($token);
echo $verified->username;  // alice
```

### 2. 启用 Redis 存储 + 防重放

```php
KodeJwt::init([
    'guards' => [
        'api' => [
            'driver'   => 'sso',
            'storage'  => 'redis',
            'algo'     => 'RS256',
            'secret'   => 'your-rs256-secret',
            'expected_claims' => [
                'iss' => 'https://auth.example.com',
                'aud' => ['api.example.com', 'mobile'],
            ],
            'clock_skew' => 30,
        ],
    ],
    'storage' => [
        'redis' => [
            'host' => '127.0.0.1',
            'port' => 6379,
            'password' => getenv('REDIS_PASSWORD'),
            'prefix' => 'kode:jwt:',
        ],
    ],
    'replay' => [
        'mode'          => 'strict',     // strict / lenient / off
        'require_nonce' => true,
        'window'        => 60,
        'max_requests'  => 5,
    ],
]);
```

### 3. 自定义 Payload 并签发

```php
use Kode\Jwt\Security\AntiReplay;

$payload = Payload::create(
    uid: 1001,
    username: 'alice',
    platform: 'web',
    exp: time() + 3600,
    iat: time(),
    jti: Payload::generateJti(),
    audience: ['api.example.com'],
    issuer:   'https://auth.example.com',
    subject:  'auth-service',
    nonce:    AntiReplay::generateNonce(16),  // 32 字节一次性 Nonce
    roles:    ['user', 'admin'],
    perms:    ['read', 'write'],
    customData: [
        'tenant_id'  => 't_42',
        'department' => 'IT',
    ],
);

$result = KodeJwt::issue($payload);
// ['token' => 'eyJ...', 'expires_in' => 3600, 'refresh_ttl' => 604800]
```

### 4. 异常处理模板

```php
use Kode\Jwt\Exception\TokenInvalidException;
use Kode\Jwt\Exception\TokenBlacklistedException;
use Kode\Jwt\Exception\TokenReplayException;
use Kode\Jwt\Exception\TokenExpiredException;

try {
    $payload = KodeJwt::authenticate($token);
} catch (TokenReplayException $e) {
    // 重放攻击：记录安全日志、触发风控告警
    return response()->json(['error' => '请求被拒绝'], 401);
} catch (TokenBlacklistedException $e) {
    // 已注销：引导重新登录
    return response()->json(['error' => '会话已过期'], 401);
} catch (TokenExpiredException $e) {
    // 已过期：尝试 refresh
    return response()->json(['error' => '需要刷新'], 401);
} catch (TokenInvalidException $e) {
    // 签名错误 / 算法不匹配 / 业务声明不匹配
    return response()->json(['error' => '无效 Token'], 401);
}
```

> 完整示例请参考 `examples/` 目录：
> - `examples/basic_usage.php` — 基础 + expected_claims 校验
> - `examples/storage_usage.php` — 多存储 + SsoStorageInterface 增强
> - `examples/advanced_usage.php` — 标准声明 + Nonce + 多签

---

## 🆕 v1.10.0 新特性：OAuth2 / OIDC 互操作能力增强

v1.10.0 聚焦 **OAuth2 / OIDC 互操作能力增强**，新增四个 RFC 标准模块：JWKS 端点发布（RFC 7517 §5）、Token Introspection（RFC 7662）、OIDC Discovery（RFC 8414）、Scope 值对象与声明检查器，并引入 `TokenPolicy` 策略对象统一管理 Token 校验逻辑。所有新模块均为 **PSR-7 / PSR-15 解耦**设计，可适配任意框架的 HTTP 层。

### 1. JWKS 端点发布（RFC 7517 §5）

`JwksPublisher` 将本地 JWK Set 以标准 JSON 格式发布到 `jwks_uri`，供资源服务器拉取公钥验签。

| 类 | 说明 |
|------|------|
| `Kode\Jwt\OAuth2\JwksPublisher` | JWKS 端点发布器，自动剥离私钥，支持 ETag / If-None-Match |
| `Kode\Jwt\OAuth2\JwksResponse` | 与 PSR-7 解耦的响应值对象（status / headers / body） |

#### 1.1 发布公开 JWK Set

```php
use Kode\Jwt\KodeJwt;
use Kode\Jwt\Key\JwkFactory;

// 1. 生成 RSA 密钥对（私钥用于签发，公钥用于发布）
$keyPair = JwkFactory::generateRsaKeyPair(2048, 'kid-2026-01');

// 2. 创建 JWKS 发布器（公钥集合自动剥离私钥参数）
$jwksSet = $keyPair['public']->toJwkSet(); // 假设已包装为 JwkSet
$publisher = KodeJwt::jwksPublisher($jwksSet, maxAge: 3600);

// 3. 处理 HTTP 请求（传入 If-None-Match 头）
$response = $publisher->handle([
    'If-None-Match' => $_SERVER['HTTP_IF_NONE_MATCH'] ?? '',
]);

// 4. 输出响应（适配你框架的 Response 对象）
http_response_code($response->status);
foreach ($response->headers as $name => $value) {
    header("{$name}: {$value}");
}
echo $response->body;
// 命中协商缓存时返回 304 Not Modified，body 为空
```

**安全设计**：
- `JwksPublisher` 内部调用 `JwkSet::toPublic()`，**永远只输出公开 JWK Set**
- ETag 基于公开 JWK Set JSON 的 sha256 强哈希，杜绝密钥内容被推断
- `Cache-Control: public, max-age=3600` 允许 CDN 缓存但不允许浏览器存储

### 2. Token Introspection（RFC 7662）

`Introspector` 提供标准 introspection 端点，资源服务器可通过它查询 Token 当前状态。

| 类 | 说明 |
|------|------|
| `Kode\Jwt\OAuth2\IntrospectionResponse` | RFC 7662 §2.2 响应值对象，`final readonly class` |
| `Kode\Jwt\OAuth2\Introspector` | 内省服务，自动完成解析验签 + 黑名单检查 |

#### 2.1 内省 Token

```php
use Kode\Jwt\KodeJwt;

// 1. 创建 Introspector（使用默认守卫）
$introspector = KodeJwt::introspector();

// 2. 内省 Token（自动完成验签 + 黑名单检查）
$response = $introspector->introspect(
    token: $bearerToken,
    expectedPlatform: 'web',
    clientId: 'client-app-001',
);

// 3. 输出 RFC 7662 标准响应
header('Content-Type: application/json');
echo $response->toJson();
// 有效 Token：{"active":true,"scope":"openid profile","client_id":"client-app-001","username":"alice","token_type":"Bearer","exp":1800000000,"iat":1700000000,"sub":"user-123","aud":"web","iss":"kode","jti":"..."}
// 无效 Token：{"active":false}
```

**信息侧通道防御**：任何失败（格式错误、签名错误、过期、黑名单、平台不匹配）统一返回 `{"active":false}`，**不向资源服务器泄露失败原因**，避免攻击者通过 introspection 响应探测系统状态。

### 3. OIDC Discovery（RFC 8414）

`DiscoveryPublisher` 发布授权服务器元数据到 `/.well-known/openid-configuration`。

| 类 | 说明 |
|------|------|
| `Kode\Jwt\OpenId\DiscoveryConfiguration` | RFC 8414 元数据值对象，`final readonly class` |
| `Kode\Jwt\OpenId\DiscoveryPublisher` | Discovery 端点发布器，支持 ETag 协商缓存 |

#### 3.1 发布 Discovery 文档

```php
use Kode\Jwt\KodeJwt;

// 1. 创建 Discovery 配置
$config = KodeJwt::discoveryConfiguration(
    issuer: 'https://auth.example.com',
    authorizationEndpoint: 'https://auth.example.com/authorize',
    tokenEndpoint: 'https://auth.example.com/token',
    jwksUri: 'https://auth.example.com/.well-known/jwks',
    userinfoEndpoint: 'https://auth.example.com/userinfo',
    introspectionEndpoint: 'https://auth.example.com/introspect',
    revocationEndpoint: 'https://auth.example.com/revoke',
);

// 2. 创建发布器并处理请求
$publisher = KodeJwt::discoveryPublisher($config, maxAge: 86400);
$response = $publisher->handle([
    'If-None-Match' => $_SERVER['HTTP_IF_NONE_MATCH'] ?? '',
]);

http_response_code($response->status);
foreach ($response->headers as $name => $value) {
    header("{$name}: {$value}");
}
echo $response->body;
```

**标准路径**：
- OIDC：`/.well-known/openid-configuration`
- OAuth2：`/.well-known/oauth-authorization-server`

### 4. Scope 值对象（RFC 6749 §3.3）

`Scope` 提供不可变集合语义，统一处理 OAuth2 / OIDC scope 的解析、校验、集合运算。

```php
use Kode\Jwt\KodeJwt;

// 1. 从 Token 中的 scope 字符串构造
$scope = KodeJwt::scope('openid profile email');

// 2. 集合运算
$scope->has('openid');              // true
$scope->hasAny(['profile', 'phone']); // true
$scope->hasAll(['openid', 'phone']); // false
$scope->intersect(['openid', 'email'])->toArray(); // ['openid', 'email']
$scope->merge(['offline_access'])->toString();     // "openid profile email offline_access"

// 3. 校验
$scope->allAllowed(['openid', 'profile', 'email', 'address']); // true
$scope->allStandard();  // true（全部为 OIDC 标准 scope）

// 4. 嵌入 Token
$scope->__toString(); // "openid profile email"（可直接作为 Payload.scope）
```

### 5. ClaimInspector 链式声明校验器

`ClaimInspector` 是无状态服务，提供链式 API 校验 Payload 声明。

```php
use Kode\Jwt\KodeJwt;
use Kode\Jwt\Exception\TokenInvalidException;

$inspector = KodeJwt::claimInspector();

try {
    $inspector
        ->assertIssuer($payload, 'https://auth.example.com')
        ->assertAudience($payload, 'web')
        ->assertSubject($payload, 'user-123')
        ->assertTimeWindow($payload, clockSkew: 30)
        ->assertScopesAll($payload, ['openid', 'profile'])
        ->assertPlatform($payload, 'web')
        ->assertCustomEquals($payload, 'tenant', 'acme');
    // 全部通过
} catch (TokenInvalidException $e) {
    // 校验失败，$e->jti 携带 Token JTI 便于排查
    error_log("Token 校验失败：{$e->getMessage()} (jti={$e->jti})");
}
```

**常量时间比较**：`assertIssuer` / `assertPlatform` / `assertSubject` 内部使用 `hash_equals`，防止时序攻击。

### 6. TokenPolicy 策略对象

`TokenPolicy` 是不可变值对象，承载完整 Token 校验策略，链式 `with*` 方法返回新实例。

```php
use Kode\Jwt\KodeJwt;

// 1. 链式构建策略
$policy = KodeJwt::tokenPolicy()
    ->withIssuer('https://auth.example.com')
    ->withAudience('web')
    ->withPlatform('web')
    ->withRequiredScopes(['openid', 'profile'])
    ->withAnyScopes(['read', 'write'])    // 至少满足一个
    ->withRequiredCustom(['tenant' => 'acme'])
    ->withClockSkew(30)
    ->withIgnoreExpiration(false);

// 2. enforce：失败抛异常
try {
    $policy->enforce($payload);
} catch (\Kode\Jwt\Exception\TokenInvalidException $e) {
    // ...
}

// 3. satisfies：不抛异常的判定版本
if ($policy->satisfies($payload)) {
    // 校验通过
}

// 4. 提取命中 scope
$allowedScope = $policy->extractAllowedScope($payload);

// 5. 序列化（用于配置缓存）
$array = $policy->toArray();
$policy2 = \Kode\Jwt\Policy\TokenPolicy::fromArray($array);
```

### 7. KodeJwt 门面便捷方法

v1.10.0 在 `KodeJwt` 门面层新增 8 个便捷方法：

| 方法 | 用途 |
|------|------|
| `KodeJwt::jwksPublisher(JwkSet, maxAge)` | 创建 JWKS 端点发布器 |
| `KodeJwt::introspector(guard)` | 创建 Introspector |
| `KodeJwt::introspect(token, platform, clientId, guard)` | 便捷内省 |
| `KodeJwt::discoveryConfiguration(issuer, ...)` | 创建 Discovery 配置 |
| `KodeJwt::discoveryPublisher(config, maxAge)` | 创建 Discovery 端点发布器 |
| `KodeJwt::tokenPolicy()` | 创建空 Token 策略 |
| `KodeJwt::claimInspector()` | 创建 Claim 检查器 |
| `KodeJwt::scope(string)` | 从字符串创建 Scope 值对象 |

### 8. 测试与质量

- 测试套件：246 个测试 / 610 个断言
- 新增测试：`JwksEndpointTest` (18) / `IntrospectionTest` (16) / `DiscoveryTest` (18) / `ScopeTest` (11) / `ClaimInspectorTest` (22) / `TokenPolicyTest` (19)
- PHPCS：0 错误 / 0 警告
- PHPStan：level 7+

---

## 🆕 v1.9.0 新特性：PHP 8.3+ + JWK 模块 + Token 指纹 + 算法白名单

v1.9.0 是一次**主版本升级**，将最低 PHP 版本提升至 8.3+，引入 JWK 密钥管理、Token 客户端指纹绑定、算法白名单三层防御，并全面应用 PHP 8.3 现代化特性。

### 1. JWK 密钥管理模块（RFC 7517 / RFC 7518）

新增 `src/Key/` 目录，提供完整的 JWK 工作流：

| 类 | 说明 |
|------|------|
| `Jwk` | `final readonly class` 值对象，表示一个 JWK，支持 RSA / EC / oct 三种 kty |
| `JwkSet` | JWK 集合，用于密钥轮换场景下按 `kid` 选择密钥 |
| `KeyConverter` | PEM ↔ JWK 互转，包含 ASN.1 DER 编码实现 RSA SubjectPublicKeyInfo 构造 |
| `JwkFactory` | CSPRNG 安全密钥生成（`random_bytes`），RSA 默认 2048 位（NIST SP 800-131A） |

#### 1.1 生成对称密钥（oct）

```php
use Kode\Jwt\Key\JwkFactory;

// 生成 HS256 密钥（32 字节）
$jwk = JwkFactory::generateOctKey('HS256');
echo $jwk->toJson();
// {"kty":"oct","k":"...","use":"sig","alg":"HS256","kid":"oct-xxxx..."}

// 自动按算法选择密钥长度：HS256=32B / HS384=48B / HS512=64B
```

#### 1.2 生成 RSA 密钥对

```php
// 默认 2048 位（最低 2048，NIST 建议）
$pair = JwkFactory::generateRsaKeyPair(bits: 2048, alg: 'RS256');

$privateJwk = $pair['private'];   // 含 d/p/q/dp/dq/qi，用于签发
$publicJwk  = $pair['public'];    // 仅含 n/e，可安全分发

// 公钥分发前可再调用 toPublic() 防御性剥离
$distributable = $privateJwk->toPublic();
```

#### 1.3 PEM ↔ JWK 互转

```php
use Kode\Jwt\Key\KeyConverter;

// PEM → JWK
$jwk = KeyConverter::rsaPublicKeyToJwk('/path/to/public.pem', kid: 'key-1', alg: 'RS256');

// JWK → PEM（仅 RSA 公钥）
$pem = KeyConverter::jwkToPem($jwk);
```

#### 1.4 JWK Set 与密钥选择

```php
use Kode\Jwt\Key\JwkSet;

$set = JwkSet::create()
    ->with($jwk1)
    ->with($jwk2);

// 按 kid 选择
$selected = $set->get('key-1');

// 按算法筛选
$candidates = $set->findByAlgorithm('RS256');

// 安全分发（自动剥离所有私钥参数）
$publicSet = $set->toPublic();
```

#### 1.5 安全设计要点

- **不可变性**：`Jwk` 使用 `final readonly class`，构造完成后无法修改任何属性，防止密钥在传递中被篡改
- **私钥隔离**：`toPublic()` 返回新实例（剥离 `d/p/q/dp/dq/qi/k` 等私钥参数），原对象仍可继续用于签发
- **脱敏 `__toString`**：`echo $jwk` 仅输出 `Jwk(kty=RSA, kid=..., alg=RS256, private=no)`，绝不泄露密钥内容
- **kid 自动生成**：使用 8 字节 CSPRNG 随机数（16 位十六进制字符串）

---

### 2. Token 客户端指纹绑定（Fingerprint）

新增 `src/Security/Fingerprint.php`，将 Token 与客户端环境（UA + IP 前缀）绑定，防止：

- Token 被截获后在不同设备/浏览器重放
- 跨网络环境重放（如开发环境 Token 流入生产）

#### 2.1 基本用法

```php
use Kode\Jwt\Security\Fingerprint;

$fp = new Fingerprint();

// 计算指纹（基于 UA + IP 前缀）
$context = [
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
    'ip'         => $_SERVER['REMOTE_ADDR'] ?? '',
];
$fingerprintHash = $fp->compute($context);

// 签发时绑定（业务层将 $fingerprintHash 写入 Payload.custom.fingerprint）
$payload = Payload::create(
    uid: 123,
    platform: 'web',
    exp: time() + 3600,
    iat: time(),
    jti: Payload::generateJti(),
    customData: ['fingerprint' => $fingerprintHash],
);

// 验证时校验
$fp->ensureMatch($context, $payload->getCustom('fingerprint'));
// 不匹配时抛出 JwtException
```

#### 2.2 安全策略

- **IP 前缀归一化**：默认使用 IPv4 `/24`、IPv6 `/64` 前缀，避免 NAT 网络下频繁切换 IP 导致误判
- **可信内网白名单**：`127.`、`10.`、`192.168.`、`172.16.`～`172.31.` 等内网 IP 自动跳过校验，避免开发/测试环境误伤
- **常量时间比较**：使用 `hash_equals()` 防止时序攻击
- **可配置字段**：支持 `ipPrefixOnly` 模式（仅校验 IP 前缀，不校验 UA），适配移动端 UA 频繁变化的场景

---

### 3. 算法白名单三层防御

`Parser::ensureAllowedAlgorithm()` 强化算法校验，杜绝算法混淆攻击（Algorithm Confusion Attack）：

```
┌─────────────────────────────────────────────────────────┐
│ 防御层 1：永久禁用 "none" 算法                            │
│   即使配置允许，"none" 也直接拒绝                          │
├─────────────────────────────────────────────────────────┤
│ 防御层 2：显式白名单（allowed_algorithms 数组）            │
│   适用于密钥轮换、多算法并存场景                           │
│   Token alg 必须命中白名单                                │
├─────────────────────────────────────────────────────────┤
│ 防御层 3：单算法严格匹配（algo 单值）                      │
│   适用于单算法场景                                        │
│   Token alg 必须与配置 algo 严格相等                       │
└─────────────────────────────────────────────────────────┘
```

#### 配置示例

```php
// 单算法场景（默认）
'guards' => [
    'api' => [
        'algo' => 'RS256',
    ],
],

// 多算法并存场景（密钥轮换）
'guards' => [
    'api' => [
        'allowed_algorithms' => ['RS256', 'RS384'],  // 显式白名单
        // 'algo' 可不设置
    ],
],
```

#### 攻击场景示例

```
攻击者构造：alg=HS256，用服务端 RS256 公钥当 HMAC 密钥签名
↓
防御层 3 触发：Token alg=HS256 ≠ 配置 algo=RS256 → 拒绝
防御层 2 触发：HS256 不在 allowed_algorithms=[RS256, RS384] 中 → 拒绝
```

---

### 4. PHP 8.3 现代化特性全面应用

| 特性 | 应用位置 | 说明 |
|------|----------|------|
| `readonly class` | `Jwk`、`JwkSet` | 整个类不可变，构造后任何属性不可修改 |
| 类型化类常量 | `Jwk::SUPPORTED_KTY`、`JwkFactory::ALG_KEY_BYTES`、`Fingerprint::DEFAULT_FIELDS` 等 | `private const array FOO = [...]` 强化类型安全 |
| `json_validate()` | `Jwk::fromJson()` | 替代 `json_decode` + `json_last_error` 检查的繁琐写法 |
| `#[\Override]` 属性 | `Jwk::toArray()`、`Jwk::toJson()`、`Jwk::__toString()` | 显式声明方法重写，防止子类意外覆盖 |

---

### 5. v1.9.0 其他重要改进

- **移除 `src/Stub/RedisStub.php`**：移除通过 `autoload.files` 全局别名化 `Redis` 类的反模式，改为运行时检测
- **存储 `set()` 默认 TTL 统一为 0**：所有存储驱动 `set($key, $value, int $ttl = 0)` 语义一致，0 表示永不过期
- **`Payload::quickCreate` 修复**：不再用 `refresh_ttl` 覆盖 `ttl`，避免 TTL 配置失效
- **`MultiSignature::findSigner` 修复**：默认 keyId 与 `sign()` 一致（`signer_{index}`）
- **`RedisStorage::getRemainingTtl` 修复**：永不过期的 Key 返回 -1 而非误报 TTL
- **`ApcuStorage::set` 修复**：主 Key 写入失败时不再写入 meta_ttl
- **`FileStorage` 防 key 碰撞**：路径增加 sha256 短哈希
- **`KeyRotationManager::getAllKeys` 优化**：使用 `getMultiple()` 批量获取，消除 N+1 查询
- **`Parser` / `Builder` 公私钥缓存**：按文件路径 + mtime 缓存，避免重复 IO
- **`BaseGuard::refresh` 优化**：提取 `canRefreshPayload()` 避免二次解析 Token

---

### 6. 测试覆盖

v1.9.0 测试套件：**145 个测试，413 个断言**，新增测试覆盖：

- `tests/JwkTest.php`（19 个测试）：Jwk 创建/序列化、kty 归一化、toPublic、fromArray/fromJson 往返、computeKid 确定性、JwkSet 操作、工厂密钥生成、RSA 与 openssl_sign/verify 端到端验证
- `tests/FingerprintTest.php`（12 个测试）：相同上下文相同哈希、不同 UA/IP 不同哈希、IP 前缀归一化、verify 匹配/失配、可信内网 IP 跳过、ensureMatch 异常、IPv6 支持、ipPrefixOnly 禁用选项

回归测试：
- `testQuickCreateDoesNotOverrideTtlWithRefreshTtl`
- `testTtlUnitSecondsIsRespected`
- `testRefreshDoesNotDoubleParseToken`

---

## 🆕 v1.8.2 优化：存储驱动全面补齐 + 安全加固

v1.8.2 聚焦于**接口完整性、安全加固、性能优化**，修复了多个 P0/P1 级别问题。

### 存储驱动接口补齐

v1.8.1 中 `ApcuStorage`、`DatabaseStorage`、`CoroutineRedisStorage`、`MemcachedStorage` 缺少 `touch`/`getRemainingTtl`/`clear` 方法，调用会触发致命错误。v1.8.2 已全部补齐：

| 存储驱动 | touch | getRemainingTtl | clear | SsoStorageInterface |
|----------|:-----:|:---------------:|:-----:|:-------------------:|
| RedisStorage | ✅ | ✅ | ✅ | ✅ |
| MemoryStorage | ✅ | ✅ | ✅ | ✅ |
| FileStorage | ✅ | ✅ | ✅ | ✅ |
| NullStorage | ✅ | ✅ | ✅ | ✅ |
| ApcuStorage | ✅ 新增 | ✅ 新增 | ✅ 新增 | ✅ 新增 |
| DatabaseStorage | ✅ 新增 | ✅ 新增 | ✅ 新增 | ✅ 新增 |
| CoroutineRedisStorage | ✅ 新增 | ✅ 新增 | ✅ 新增 | ✅ 新增 |
| MemcachedStorage | ✅ 新增 | ✅ 新增 | ✅ 新增 | ✅ 新增 |

### 安全加固

- **移除弱密钥默认值**：`KodeJwt::getDefaultConfig()` 中 `secret` 改为空字符串，强制用户配置
- **移除伪随机 fallback**：`AntiReplay::generateNonce()` 在 `random_bytes` 失败时抛异常而非降级
- **DatabaseStorage 表名注入防护**：构造函数中用正则校验表名
- **DatabaseStorage PDO 安全选项**：强制 `ATTR_EMULATE_PREPARES = false`
- **CoroutineRedisStorage 惰性加载**：移除顶部 `use Swoole\Coroutine\Redis` 硬依赖，改为运行时检测

### 性能优化

- **TokenManager N+1 查询修复**：`getUserTokens()` 改用 `getMultiple()` 批量获取
- **Parser RSA 公钥缓存**：`verifyRsa()` 缓存已解析的公钥资源，避免重复磁盘 IO
- **DatabaseStorage 概率清理**：读操作中 `cleanExpired()` 改为 1% 概率触发，不再每次全表扫描
- **FileStorage 紧凑 JSON**：`set()`/`touch()` 移除 `JSON_PRETTY_PRINT`，减少 IO 开销
- **FileStorage 共享锁读取**：`get()`/`has()` 改用 `flock(LOCK_SH)` 读取，与 `set()` 的 `LOCK_EX` 对称

### DatabaseStorage SQL 方言自动适配

v1.8.2 之前 `DatabaseStorage` 硬编码 SQLite 方言（`AUTOINCREMENT`、`INSERT OR REPLACE`、`strftime`），但默认 DSN 是 MySQL，导致 MySQL 下不可用。现已根据 DSN 自动检测驱动类型：

```php
// SQLite 方言
'INSERT OR REPLACE INTO ...'

// MySQL 方言
'INSERT ... ON DUPLICATE KEY UPDATE ...'
```

### MemcachedStorage addServers 修复

v1.8.2 修复了 `addServers` 参数结构 Bug：配置中的关联数组（`['host' => ..., 'port' => ..., 'weight' => ...]`）现在会自动转换为索引数组（`[$host, $port, $weight]`）。

### 全局 `declare(strict_types=1)`

以下文件补充了 `declare(strict_types=1);`，符合 PSR-12 规范：

`TokenManager`、`StorageFactory`、`GuardInterface`、`FileStorage`、`NullStorage`、`ApcuStorage`、`DatabaseStorage`、`CoroutineRedisStorage`、`MemcachedStorage`、`RedisStorage`

---

## 🆕 v1.8.1 新特性：SsoStorageInterface 能力探测

v1.8.1 引入了 `Kode\Jwt\Contract\SsoStorageInterface`，用于描述存储后端的"高级 SSO 能力"。

- 所有存储实现（Redis、Memory、File 等）仍只需实现基础 `StorageInterface`；
- 支持 SSO / 原子化撤销 / 用户活跃 Token 列表 的存储后端，可选实现 `SsoStorageInterface`；
- 业务代码通过 `instanceof` 进行能力探测，自动使用高级 API，缺失时降级为通用实现。

### 接口契约

```php
namespace Kode\Jwt\Contract;

interface SsoStorageInterface extends StorageInterface
{
    /** 原子化撤销（黑名单 + SSO 清理 + 用户列表清理 + 详情清理） */
    public function atomicRevoke(string $jti, string $uid, string $platform, int $ttl = 3600): int;

    /** 记录到用户活跃 Token 列表（最多保留 50 条） */
    public function trackUserToken(string $uid, string $platform, string $jti, int $ttl = 0): bool;

    /** 设置 SSO 平台 → JTI 映射 */
    public function setSsoMapping(string $uid, string $platform, string $jti, int $ttl = 0): bool;

    /** 获取 SSO 平台 → JTI 映射 */
    public function getSsoMapping(string $uid, string $platform): ?string;
}
```

### 业务代码推荐写法

```php
use Kode\Jwt\Contract\SsoStorageInterface;

/** @var \Kode\Jwt\Contract\StorageInterface $storage */

// 通用调用：所有存储后端都支持
$storage->blacklist($jti, 3600);

// 高级能力：仅在支持时使用，否则降级
if ($storage instanceof SsoStorageInterface) {
    // 推荐：原子化撤销（生产环境使用 Redis 时为 Lua 脚本原子操作）
    $affected = $storage->atomicRevoke($jti, $uid, $platform, 3600);

    // 维护用户活跃 Token 列表
    $storage->trackUserToken($uid, $platform, $jti, 3600);

    // SSO 平台 → JTI 映射
    $storage->setSsoMapping($uid, $platform, $jti, 3600);
    $bound = $storage->getSsoMapping($uid, $platform);
} else {
    // 降级实现（顺序执行，非原子）
    $storage->blacklist($jti, 3600);
    $storage->delete("sso:{$uid}:{$platform}");
    $storage->delete("token:{$jti}");
}
```

### 已实现 SsoStorageInterface 的存储

| 存储 | 实现方式 | 适用场景 |
|------|----------|----------|
| `RedisStorage` | Lua 脚本（`LUA_ATOMIC_REVOKE`） | 生产环境首选，原子性最强 |
| `CoroutineRedisStorage` | 协程 Redis + Lua | Swoole 等协程环境 |
| `MemoryStorage` | 顺序执行（PHP-FPM 单进程语义） | 单机测试、本地开发 |
| `FileStorage` | 顺序执行（文件锁语义） | 单机持久化场景 |

> **关于不可变 Payload 的说明**：v1.8.1 起，`Payload` 为 `readonly` 类，
> `setEncryptedData()` 改为返回**新实例**而非修改原实例，
> 调用方式：`$newPayload = $payload->setEncryptedData('...')`。

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
- **持久化连接**：Redis 存储支持 `persistent` 长连接，跨请求复用连接

---

## 🛡️ Redis 黑名单与防重放（v1.8.0+）

> **核心目标**：在传统的 JTI 黑名单之上，引入 Nonce 一次性消费与滑动窗口机制，
> 形成"两层防御"——既能在注销后立即拦截，又能在 Token 有效期内阻断重放。

### 1. Redis 黑名单策略

`kode/jwt` 默认将 `storage` 设为 `redis`，通过以下键完成 Token 生命周期管理：

| 键名 | 用途 | 生命周期 |
|------|------|----------|
| `kode:jwt:blacklist:{jti}` | 注销/封禁的 JTI 集合 | `exp + refresh_ttl` |
| `kode:jwt:token:{jti}` | Token 详细快照（uid、平台、过期时间等） | `exp - now` |
| `kode:jwt:sso:{uid}:{platform}` | SSO 平台→JTI 映射 | `exp + refresh_ttl` |
| `kode:jwt:user:{uid}:{platform}:tokens` | 用户活跃 Token 列表（最近 50 条） | `exp + refresh_ttl` |
| `kode:jwt:replay:nonce:{jti}:{nonce}` | 防重放 Nonce 一次性消费标记 | `exp - now` |
| `kode:jwt:replay:window:{jti}` | 滑动窗口访问轨迹（ZSet） | 窗口大小 |

#### 1.1 启用 Redis 存储

```php
return [
    'guards' => [
        'api' => [
            'driver'   => 'sso',
            'storage'  => 'redis',           // 指定 Redis 存储
            'algo'     => 'RS256',
            'ttl'      => 3600,
            'refresh_ttl' => 604800,
            'blacklist_enabled' => true,      // 启用黑名单
        ],
    ],
    'storage' => [
        'redis' => [
            'host' => '127.0.0.1',
            'port' => 6379,
            'password' => getenv('REDIS_PASSWORD'),
            'database' => 0,
            'prefix' => 'kode:jwt:',
            'persistent' => true,             // 长连接（可选）
            'persistent_id' => 'kode_jwt',
        ],
    ],
];
```

#### 1.2 主动注销（踢下线）

```php
// 用户主动退出登录
KodeJwt::guard('api')->invalidate($token);

// 强制注销某用户某平台所有 Token
$count = KodeJwt::revokeUserTokens('123', 'app');

// 强制注销某用户所有平台 Token
$count = KodeJwt::revokeUserTokens('123');
```

在 SSO 模式下，新用户登录会自动调用 `atomicRevoke` Lua 脚本，
一次性清理旧 Token 的黑名单、SSO 映射、用户列表、Token 详情四个键，
避免"半撤销"状态导致的并发漏洞。

### 2. 防重放攻击（Anti-Replay）

#### 2.1 攻击场景

```
[客户端] ——A: 请求 (Token: eyJ...)→  [服务器]
                                          ↓ (Token 被截获)
[攻击者] ——B: 重复使用 Token eyJ...→  [服务器]
```

仅依赖 JTI 黑名单无法应对以下两种情况：
1. 注销前的"中间人重放"：Token 还在有效期内，被攻击者重发。
2. 高频试探：攻击者在短时间内用同一 Token 暴力请求敏感接口。

#### 2.2 Nonce 一次性消费

```php
return [
    'replay' => [
        'mode'         => 'strict',          // strict / lenient / off
        'require_nonce' => true,             // 强制要求 Nonce 字段
        'backend'      => 'redis',
        'redis_storage'=> 'redis',
        'prefix'       => 'kode:jwt:',
        'ttl'          => 3600,              // Nonce 保留时间（秒）
    ],
];
```

启用后，签发 Token 时会自动注入 `nonce` 字段：

```php
$payload = Payload::create(
    uid: 123,
    platform: 'web',
    exp: time() + 3600,
    iat: time(),
    jti: Payload::generateJti(),
    nonce: AntiReplay::generateNonce(16),    // 32 字节随机值
);
$token = KodeJwt::guard('api')->issue($payload);
```

验证流程：

```
[1] 解析 Token → 取出 jti、nonce
[2] Redis EVAL "SET NX" →  首次消费返回 1，重放返回 0
[3] 命中重放 → 抛出 TokenReplayException
```

#### 2.3 滑动窗口频率限制

当 `mode = lenient` 时启用，可识别异常短时间高频重放：

```php
return [
    'replay' => [
        'mode'         => 'lenient',
        'window'       => 60,                // 窗口大小（秒）
        'max_requests' => 5,                // 窗口内最大允许次数
    ],
];
```

底层使用 Redis ZSet 维护"最近 N 秒的 Nonce 时间序列"，
过期窗口外的记录自动被裁剪。

#### 2.4 异常处理

```php
use Kode\Jwt\Exception\TokenReplayException;
use Kode\Jwt\Exception\TokenBlacklistedException;

try {
    $payload = KodeJwt::guard('api')->authenticate($token);
} catch (TokenReplayException $e) {
    // 重放攻击：记录安全日志、触发风控告警
    security_log('replay_attack', [
        'jti'    => $e->getJti(),
        'nonce'  => $e->getNonce(),
        'time'   => $e->getReplayDetectedAt(),
    ]);
    return response()->json(['error' => '请求被拒绝'], 401);
} catch (TokenBlacklistedException $e) {
    // 已注销：引导重新登录
    return response()->json(['error' => '会话已过期'], 401);
}
```

### 3. 标准声明（iss / aud / sub）强制校验

```php
return [
    'guards' => [
        'api' => [
            'algo' => 'RS256',
            'expected_claims' => [
                'iss' => 'https://auth.example.com',     // 签发者必须匹配
                'aud' => ['api.example.com', 'mobile'],  // 受众命中其一即可
                'sub' => 'auth-service',                 // 主体标识
                'tenant_id' => 'tenant_42',              // 自定义声明精确匹配
            ],
        ],
    ],
];
```

服务端验证流程会自动比对：
- `iss` 精确匹配
- `aud` 列表求交集
- `sub` 精确匹配
- 其他声明：精确匹配

### 4. 时钟漂移容忍

```php
return [
    'guards' => [
        'api' => [
            'clock_skew' => 30,    // 允许 30 秒的时钟漂移
        ],
    ],
];
```

适用于多节点部署、NTP 同步存在偏差的场景，
避免由于本地时间略快/略慢导致的 `nbf`、`exp` 误判。

### 5. 密钥管理建议

- **生产环境**：使用 RS256 非对称加密，私钥放在 `storage/keys/`，加入 `.gitignore`。
- **多租户隔离**：使用 `expected_claims.tenant_id` 防止跨租户 Token 混用。
- **密钥轮换**：使用内置的 `KeyRotationManager` 滚动更新密钥，详见"高级特性"章节。
- **环境变量**：将密码、Redis 凭据存放于 `.env`，切勿硬编码进代码。

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

## 🚀 高级特性

### JWT 多签（Detached Signature）

支持多个签名者对同一 Payload 进行签名，适用于多方信任场景：

```php
use Kode\Jwt\Token\Builder;

$builder = new Builder(['algo' => 'HS256']);
$builder->setUid(123);
$builder->setExpiration(time() + 3600);

// 多签配置
$signers = [
    ['key' => 'secret_key_1', 'keyId' => 'signer_a'],
    ['key' => 'secret_key_2', 'keyId' => 'signer_b'],
];

// 生成多签 JWS
$multiSigToken = $builder->buildMultiSignature($signers);

// 生成分离式签名
$detachedSig = $builder->buildDetachedSignature($signers);
```

### OpenID Connect 支持

集成 OpenID Connect 协议，支持 ID Token 生成和用户信息管理：

```php
use Kode\Jwt\OpenId\IdTokenBuilder;
use Kode\Jwt\OpenId\UserInfo;

// 构建 ID Token
$idTokenBuilder = new IdTokenBuilder([
    'secret' => 'your-secret',
    'issuer' => 'https://your-app.com',
]);

$idTokenBuilder
    ->setSubject('user-123')
    ->setAudience('client-app-id')
    ->setIssuer('https://your-app.com')
    ->setNonce('random-nonce-value')
    ->setAuthTime(time())
    ->setScopes(['openid', 'profile', 'email']);

$idToken = $idTokenBuilder->build();

// 用户信息
$userInfo = UserInfo::fromPayload($payload);
echo $userInfo->email;
echo $userInfo->name;
```

### OAuth2 混合模式

支持 JWT 与 OAuth2 授权流程的混合使用：

```php
use Kode\Jwt\OAuth2\HybridProvider;

$provider = new HybridProvider([
    'secret' => 'your-secret',
    'access_token_ttl' => 3600,
    'refresh_token_ttl' => 86400,
    'issuer' => 'https://your-app.com',
]);

// Authorization Code 模式
$tokens = $provider->generateAuthorizationCodeTokens(
    clientId: 'client-app',
    userId: 123,
    scopes: ['openid', 'profile'],
    nonce: 'random-nonce'
);

// Implicit 模式
$tokens = $provider->generateImplicitTokens(
    clientId: 'client-app',
    userId: 123,
    scopes: ['openid'],
    state: 'state-value'
);

// Client Credentials 模式
$tokens = $provider->generateClientCredentialsTokens(
    clientId: 'client-app',
    scopes: ['api:read']
);
```

### JWT 密钥轮换机制

支持密钥平滑过渡，旧密钥在过渡期内仍可用于验证：

```php
use Kode\Jwt\KeyRotation\KeyRotationManager;
use Kode\Jwt\Storage\MemoryStorage;

$storage = new MemoryStorage();
$rotationManager = new KeyRotationManager(
    storage: $storage,
    keyType: 'hmac',
    defaultKeyLifetime: 2592000,  // 30 天
    transitionPeriod: 604800      // 7 天过渡期
);

// 生成新主密钥
$newKey = $rotationManager->generateNewKey();

// 获取签名密钥（当前主密钥）
$signingKey = $rotationManager->getSigningKey();

// 获取验证密钥列表（主密钥 + 过渡期内旧密钥）
$verificationKeys = $rotationManager->getVerificationKeys();

// 自动轮换（主密钥即将过期时触发）
$rotationManager->autoRotate(86400); // 提前 1 天轮换

// 查看轮换状态
$status = $rotationManager->getRotationStatus();
```

### Prometheus 监控指标

提供 Token 相关的监控指标，便于集成 Prometheus：

```php
use Kode\Jwt\Metrics\PrometheusMetrics;

$metrics = new PrometheusMetrics('kode_jwt');

// 记录 Token 操作
$metrics->recordTokenIssued('api', 'web');
$metrics->recordTokenAuthenticated('api');
$metrics->recordTokenRefreshed('api');
$metrics->recordTokenInvalidated('api');
$metrics->recordAuthenticationFailure('expired', 'api');

// 更新统计值
$metrics->setActiveTokens(150, 'api');
$metrics->setBlacklistedTokens(12, 'api');

// 计时操作
$result = $metrics->timeOperation('authenticate', function() use ($token) {
    return KodeJwt::authenticate($token);
});

// 导出 Prometheus 格式
echo $metrics->export();
// 输出:
// # HELP kode_jwt_tokens_issued_total Total count of tokens_issued_total
// # TYPE kode_jwt_tokens_issued_total counter
// kode_jwt_tokens_issued_total{guard="api",platform="web"} 1
```

### CLI Token 管理

通过命令行管理 Token：

```bash
# 生成 Token
php bin/jwt token generate --uid=123 --username=john --platform=web

# 验证 Token
php bin/jwt token verify --token=eyJ...

# 刷新 Token
php bin/jwt token refresh --token=eyJ...

# 注销 Token
php bin/jwt token invalidate --token=eyJ...

# 查看 Token 信息
php bin/jwt token info --token=eyJ...
```

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

#### 防重放保护（v1.8.0+）

```php
// 获取防重放保护器
$replay = KodeJwt::antiReplay(): ?AntiReplay;

// 生成一次性 Nonce（32 字节随机值）
$nonce = AntiReplay::generateNonce(16);

// 手动消费 Nonce（高级用法，通常由 Guard 自动调用）
$passed = $replay->check($jti, $nonce, $ttl);

// 查询 Nonce 是否已被消费
$seen = $replay->seen($jti, $nonce);

// 检查是否启用
$enabled = $replay->isEnabled();
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
| `nonce` | `string\|null` | 🆕 一次性随机值（防重放） |
| `audience` | `string\|array\|null` | 🆕 受众（aud） |
| `issuer` | `string\|null` | 🆕 签发者（iss） |
| `subject` | `string\|null` | 🆕 主体（sub） |

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

// 🆕 获取一次性 Nonce
$nonce = $payload->getNonce(): ?string;

// 🆕 获取受众（aud）
$aud = $payload->getAudience(): string|array|null;

// 🆕 获取签发者（iss）
$iss = $payload->getIssuer(): ?string;

// 🆕 获取主体（sub）
$sub = $payload->getSubject(): ?string;

// 🆕 生成高熵 JTI（32 字节随机值）
$jti = Payload::generateJti(): string;
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

- PHP >= 8.3
- ext-json
- ext-openssl

### 可选依赖

- ext-redis：Redis 存储驱动
- ext-apcu：APCu 存储驱动
- ext-memcached：Memcached 存储驱动
- ext-pdo：数据库存储驱动
- ext-swoole：Swoole 协程支持

### 兼容环境

- PHP-FPM
- Swoole
- RoadRunner
- ReactPHP
- Amp

---