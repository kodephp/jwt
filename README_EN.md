# Kode JWT: A Robust, Comprehensive, Modern PHP 8.3+ JWT Package

> **Project Name**: `kode/jwt`
> **Current Version**: `v1.9.0`
> **Goal**: Provide a secure, flexible, high-performance JWT authentication solution for modern PHP applications, supporting Single Sign-On (SSO), Multi-Login, blacklist management, automatic renewal, multi-platform adaptation, Anti-Replay, JWK key management (RFC 7517), Token client fingerprint binding, and compatibility with FPM, Swoole, RoadRunner, and other runtime environments.

---

## 📌 Project Vision

Build a **production-grade, zero-invasion, highly extensible** JWT package designed specifically for PHP 8.3+, making full use of modern PHP features (`readonly class`, typed class constants, `json_validate()`, `#[\Override]` attribute, `enum`, union types, reflection optimization), and supporting seamless integration with mainstream frameworks (Laravel, Symfony, ThinkPHP, Hyperf, EasySwoole, etc.).

Quickly integrate using kode-related packages or other suitable general-purpose packages.

---

## 🚀 Core Features

| Feature | Description |
|---------|-------------|
| ✅ **PHP 8.3+ Native Support** | Uses `readonly class`, typed class constants (`private const array FOO = [...]`), `json_validate()`, `#[\Override]` attribute, `enum`, union types, and other modern features |
| ✅ **Multi-platform Support** | H5, PC, App, mini-programs (WeChat/Alipay/Douyin), etc., distinguished by `platform` declaration, with configurable platform settings |
| ✅ **Single Sign-On (SSO)** | Only one valid Token per user per platform |
| ✅ **Multi-Login (MLO)** | Supports simultaneous login on multiple devices for the same user |
| ✅ **Token Blacklist** | Supports active logout, forced offline, based on Redis or memory storage (coroutine-safe) |
| ✅ **Automatic Renewal (Refresh)** | Supports sliding expiration, fixed refresh cycle to prevent frequent login |
| ✅ **Multi-environment Configuration** | Supports `config/jwt.php` configuration, compatible with Laravel, Hyperf, and other frameworks |
| ✅ **Runtime Compatibility** | Supports FPM, Swoole multi-process/coroutine, RoadRunner multi-thread |
| ✅ **Type Safety & Reflection Optimization** | Uses `ReflectionClass` + caching for high-performance dependency injection and configuration parsing |
| ✅ **Contravariance/Covariance Design** | Interface design follows LSP, supports generic-style extension (via PHPDoc + naming conventions) |
| ✅ **Zero Framework Dependency** | Can be used independently or integrated into any framework via adapters |
| ✅ **Event-driven** | Provides event hooks such as `TokenIssued`, `TokenExpired`, `TokenRevoked` |
| ✅ **Audit Log** | Optional logging of Token generation, usage, and revocation behavior using general logging packages |
| ✅ **Pluggable Encryption Algorithm** | Default `HS256` / `RS256`, supports custom signers |
| ✅ **Anti-Replay** | Based on Redis Nonce + sliding window to prevent Token replay attacks |
| ✅ **High-entropy JTI** | 32-byte (256-bit) cryptographically secure random number, far higher than UUID v4 |
| ✅ **Standard Claims (iss/aud/sub)** | Business-level forced validation to prevent cross-service/cross-tenant misuse |
| ✅ **Clock Skew Tolerance** | Configurable `clock_skew` for NTP deviation scenarios in multi-node deployments |
| ✅ **Redis Atomic Revocation** | Lua script guarantees "blacklist + SSO mapping + user Token list" three-step atomicity |
| 🆕 v1.9 **JWK Key Management (RFC 7517)** | `Jwk` / `JwkSet` / `KeyConverter` / `JwkFactory`, supports RSA / EC / oct key types, PEM ↔ JWK conversion, CSPRNG secure key generation |
| 🆕 v1.9 **Token Client Fingerprint Binding** | `Fingerprint` component binds Token to client UA + IP prefix, prevents cross-device replay, with built-in trusted intranet IP whitelist |
| 🆕 v1.9 **Algorithm Allowlist Three-Layer Defense** | Permanently disable `none` algorithm → explicit allowlist → single algorithm strict matching, prevents algorithm confusion attacks |
| 🆕 v1.9 **PHP 8.3 readonly class** | Core value objects like `Jwk`, `JwkSet` use `final readonly class`, immutable at runtime to prevent key tampering |
| 🆕 v1.9 **Typed Class Constants** | Uses `private const array SUPPORTED_KTY = [...]` and other PHP 8.3 typed constants for stronger type safety |

---

## 📁 Project Structure (PSR-4)

```bash
src/
├── Contract/           # All interface definitions
│   ├── TokenManagerInterface.php
│   ├── StorageInterface.php
│   ├── GuardInterface.php
│   ├── SsoStorageInterface.php
│   └── EventInterface.php
├── Token/              # Token core classes
│   ├── Builder.php
│   ├── Parser.php       # Algorithm allowlist three-layer defense
│   ├── Claim.php
│   ├── Payload.php      # readonly value object
│   └── TokenManager.php
├── Guard/              # Guard mechanisms
│   ├── BaseGuard.php
│   ├── SsoGuard.php
│   └── MloGuard.php
├── Storage/            # Storage drivers
│   ├── RedisStorage.php
│   ├── CoroutineRedisStorage.php
│   ├── MemoryStorage.php
│   ├── FileStorage.php
│   ├── ApcuStorage.php
│   ├── DatabaseStorage.php
│   ├── MemcachedStorage.php
│   └── NullStorage.php
├── Key/                # 🆕 v1.9 JWK key management (RFC 7517)
│   ├── Jwk.php          # final readonly class value object
│   ├── JwkSet.php       # JWK Set for key rotation
│   ├── KeyConverter.php # PEM ↔ JWK conversion (ASN.1 DER)
│   └── JwkFactory.php   # CSPRNG secure key generation
├── KeyRotation/        # Key rotation
│   ├── KeyRotationManager.php
│   └── KeyVersion.php
├── Security/           # Security components
│   ├── AntiReplay.php   # Nonce one-time consumption + sliding window
│   └── Fingerprint.php  # 🆕 v1.9 Client fingerprint binding (UA + IP prefix)
├── Signature/          # Multi-signature
│   ├── MultiSignature.php
│   └── SignatureResult.php
├── Event/              # Event system
│   ├── BaseEvent.php
│   ├── EventDispatcher.php
│   ├── TokenIssued.php
│   ├── TokenExpired.php
│   ├── TokenRefreshed.php
│   ├── TokenRevoked.php
│   ├── TokenBlacklisted.php
│   └── TokenValidated.php
├── Exception/          # Custom exceptions
│   ├── JwtException.php
│   ├── TokenInvalidException.php
│   ├── TokenExpiredException.php
│   ├── TokenBlacklistedException.php
│   └── TokenReplayException.php
├── Config/             # Configuration management
│   └── ConfigLoader.php
├── Enum/               # Enums
│   ├── Algorithm.php
│   ├── GuardMode.php
│   └── StorageType.php
├── Log/                # Log adapters
├── Metrics/            # Monitoring metrics
├── OAuth2/             # OAuth2 hybrid mode
├── OpenId/             # OpenID Connect
├── Support/            # Helpers
├── Console/            # CLI commands
└── KodeJwt.php         # Main facade/factory class
```

---

## 🛠️ Installation

```bash
composer require kode/jwt
```

### CLI Tool Initialization

After installation, run the following command in your project root directory to generate the configuration file and keys:

```bash
# Navigate to your project directory
cd /path/to/your/project

# Install configuration file and generate keys (RSA key pair + HMAC key)
php vendor/bin/jwt install

# Or generate only the configuration file
php vendor/bin/jwt install --config-only

# Or generate only the keys
php vendor/bin/jwt install --key-only

# Force overwrite existing files
php vendor/bin/jwt install --force
```

#### CLI Commands Reference

| Command | Description |
|---------|-------------|
| `jwt install` | Generate configuration file and keys |
| `jwt install --config-only` | Generate only configuration file |
| `jwt install --key-only` | Generate only keys |
| `jwt install --force` | Force overwrite existing files |
| `jwt key:generate` | Generate new key pair |
| `jwt key:generate --algorithm=RS256` | Generate keys with specific algorithm |
| `jwt key:generate --force` | Force overwrite existing keys |
| `jwt help` | Display help information |

#### Key Generation Options

| Option | Description |
|--------|-------------|
| `--algorithm` | Encryption algorithm (HS256, RS256, ES256), default: RS256 |
| `--force` | Force overwrite existing keys |
| `--bits` | Key length for RSA (2048, 4096), default: 2048 |
| `--symmetric` | Generate symmetric key (HMAC) |

### Directory Structure After Installation

After running `jwt install`, the following files will be created in your project:

```bash
your-project/
├── config/
│   └── jwt.php          # JWT configuration file
├── storage/
│   └── keys/
│       ├── private.pem  # Private key (RS256/ES256)
│       └── public.pem   # Public key (RS256/ES256)
│       └── secret.key   # Symmetric key (HS256)
└── vendor/
    └── bin/
        └── jwt          # CLI tool entry point
```

---

## 🧩 Configuration File (`config/jwt.php`)

```php
<?php

return [
    'defaults' => [
        'guard' => 'api',
        'provider' => 'users',
        'platform' => 'web',
    ],

    'guards' => [
        'api' => [
            'driver' => 'kode',
            'provider' => 'users',
            'storage' => 'redis',
            'blacklist_enabled' => true,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'ttl' => 1440,
            'algo' => 'RS256',
            'secret' => null,
            'public_key' => null,
            'private_key' => null,
        ],
    ],

    'providers' => [
        'users' => [
            'model' => App\Models\User::class,
            'identifier' => 'uid',
        ],
    ],

    'platforms' => [
        'web',
        'h5',
        'pc',
        'app',
        'wx_mini',
        'ali_mini',
        'tt_mini',
    ],

    'storage' => [
        'redis' => [
            'connection' => 'default',
            'prefix' => 'kode:jwt:',
        ],
        'memory' => [
            'limit' => 10000,
        ],
    ],

    'sso' => [
        'enabled' => true,
        'max_devices' => 5,
        'allow_device_override' => true,
    ],

    'mlo' => [
        'enabled' => true,
        'max_devices' => 999,
    ],

    'events' => [
        'enabled' => true,
        'listeners' => [
            \App\Listeners\OnTokenIssued::class,
            \App\Listeners\OnTokenRevoked::class,
        ],
    ],
];
```

### Configuration Options Description

| Configuration Section | Option | Description |
|----------------------|--------|-------------|
| **defaults** | `guard` | Default guard name |
| | `provider` | Default user provider |
| | `platform` | Default platform |
| **guards** | `driver` | Guard driver (kode) |
| | `provider` | User provider for this guard |
| | `storage` | Storage driver (redis/memory/null) |
| | `blacklist_enabled` | Enable token blacklist |
| | `refresh_enabled` | Enable token refresh |
| | `refresh_ttl` | Refresh token TTL (minutes) |
| | `ttl` | Token TTL (minutes) |
| | `algo` | Signature algorithm (HS256/RS256/ES256) |
| | `secret` | Symmetric key (HS256) |
| | `public_key` | Public key path (RS256/ES256) |
| | `private_key` | Private key path (RS256/ES256) |
| **platforms** | - | Supported platform list |
| **storage** | `connection` | Redis connection name |
| | `prefix` | Key prefix for isolation |
| **sso** | `enabled` | Enable single sign-on |
| | `max_devices` | Maximum devices per user |
| | `allow_device_override` | Allow per-user device limit |
| **mlo** | `enabled` | Enable multi-login |
| | `max_devices` | Maximum concurrent devices |

### Platform-specific Configuration

```php
'guards' => [
    'app' => [
        'driver' => 'kode',
        'provider' => 'users',
        'storage' => 'redis',
        'ttl' => 43200,      // 30 days for mobile
        'refresh_ttl' => 604800,  // 7 days
        'algo' => 'RS256',
    ],
    'web' => [
        'driver' => 'kode',
        'provider' => 'users',
        'storage' => 'redis',
        'ttl' => 1440,       // 24 hours for web
        'refresh_ttl' => 20160,
        'algo' => 'RS256',
    ],
],
```

---

## 🔐 Core Class Design (Examples)

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
     * Create Payload instance from array
     * 
     * @param array $data Array containing Payload data
     * @return static
     * @throws \InvalidArgumentException When required fields are missing
     */
    public static function fromArray(array $data): static
    {
        // Validate required fields
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
     * Create a Payload instance with custom data
     * 
     * @param int|string|null $uid User ID (supports string types like snowflake ID)
     * @param string|null $username Username
     * @param string $platform Platform identifier
     * @param int $exp Expiration timestamp
     * @param int $iat Issued timestamp
     * @param string $jti JWT ID
     * @param array|null $roles User role list
     * @param array|null $perms User permission list
     * @param array|string|null $customData Custom data, can be array or encrypted string
     * @return static
     */
    public static function create(
        int|string|null $uid = null,
        ?string $username = null,
        string $platform,
        int $exp,
        int $iat,
        string $jti,
        ?array $roles = null,
        ?array $perms = null,
        array|string|null $customData = null
    ): static {
        $custom = [];

        // Handle custom data
        if (is_string($customData)) {
            // If it's a string, store it as encrypted data
            $custom['encrypted_data'] = $customData;
        } elseif (is_array($customData)) {
            // If it's an array, merge directly into custom field
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

---

## 🧪 Usage Examples (Laravel / Hyperf)

### 1. Generate Token

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

// Returns: ['token' => 'eyJ...', 'expires_in' => 1440, 'refresh_ttl' => 20160]
```

### 2. Validate Token

```php
try {
    $payload = KodeJwt::guard('api')->authenticate($token);
    echo $payload->username; // john_doe
} catch (TokenInvalidException $e) {
    // Handle exception
}
```

### 3. Refresh Token

```php
$newToken = KodeJwt::guard('api')->refresh($oldToken);
```

### 4. Invalidate Token (Add to Blacklist)

```php
KodeJwt::guard('api')->invalidate($token);
```

### 5. Using Convenience Methods

```php
// Using Builder's convenience methods
$token = KodeJwt::builder()
    ->setUid(123)
    ->setUsername('john_doe')
    ->setPlatform('app')
    ->setRoles(['user'])
    ->setPermissions(['read', 'write'])
    ->setCustom(['department' => 'IT'])
    ->issue();

// Get all active tokens for a user
$tokens = KodeJwt::getUserTokens('123', 'app');

// Force logout all tokens for a user
$count = KodeJwt::revokeUserTokens('123', 'app');

// Check if token is valid
$isValid = KodeJwt::isTokenValid($token);

// Get token detailed information
$info = KodeJwt::getTokenInfo($token);
// Returns: ['uid' => 123, 'platform' => 'app', 'exp' => 1234567890, ...]

// Clean expired tokens
$cleanedCount = KodeJwt::cleanExpired();

// Get storage statistics
$stats = KodeJwt::getStats();
// Returns: ['total' => 100, 'expired' => 20, 'active' => 80]

// Using enhanced Payload creation methods
// 1. Using array custom data
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
            'language' => 'en-US'
        ]
    ]
);

// 2. Using encrypted string custom data
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

### 6. Single Sign-On (SSO) Usage

SSO ensures only one valid Token per user per platform. When a user logs in on a new device, their previous Token on that platform is automatically invalidated.

```php
use Kode\Jwt\KodeJwt;

// User logs in from a new device
$payload = new Payload(
    uid: 123,
    username: 'john_doe',
    platform: 'app',
    exp: time() + 86400,
    iat: time(),
    jti: uniqid('jwt_'),
    roles: ['user']
);

$token = KodeJwt::guard('api')->issue($payload);

// The previous Token for user 123 on 'app' platform is now invalid
// Any attempt to use the old Token will fail with TokenInvalidException
```

### 7. Multi-Login (MLO) Usage

MLO allows multiple concurrent logins for the same user across different devices.

```php
use Kode\Jwt\KodeJwt;

// Login from multiple devices
$tokens = [];

// Device 1: Mobile App
$payload1 = Payload::create(
    uid: 123,
    username: 'john_doe',
    platform: 'app',
    exp: time() + 86400,
    iat: time(),
    jti: uniqid('jwt_')
);
$tokens['mobile'] = KodeJwt::guard('api')->issue($payload1);

// Device 2: Web Browser
$payload2 = Payload::create(
    uid: 123,
    username: 'john_doe',
    platform: 'web',
    exp: time() + 86400,
    iat: time(),
    jti: uniqid('jwt_')
);
$tokens['web'] = KodeJwt::guard('api')->issue($payload2);

// Device 3: WeChat Mini Program
$payload3 = Payload::create(
    uid: 123,
    username: 'john_doe',
    platform: 'wx_mini',
    exp: time() + 86400,
    iat: time(),
    jti: uniqid('jwt_')
);
$tokens['wechat'] = KodeJwt::guard('api')->issue($payload3);

// All three tokens are valid simultaneously
// Get all active tokens for a user
$activeTokens = KodeJwt::getUserTokens(123);
// Returns an array of all active tokens across platforms

// Force logout a specific token
KodeJwt::guard('api')->invalidate($tokens['mobile']);

// Force logout all tokens for a user across all platforms
$count = KodeJwt::revokeUserTokens(123);
```

### 8. Token Refresh with Sliding Expiration

When refreshing a Token, the expiration time extends, providing a seamless user experience while maintaining security.

```php
use Kode\Jwt\KodeJwt;

// Current token is about to expire
$currentToken = 'eyJ...';

// Refresh the token (extends expiration time)
$newToken = KodeJwt::guard('api')->refresh($currentToken);

// Returns: ['token' => 'new_eyJ...', 'expires_in' => 1440, 'refresh_ttl' => 20160]
// The new token has a fresh expiration time from now
```

### 9. Platform-specific Token Management

Different platforms can have different token configurations and behaviors.

```php
use Kode\Jwt\KodeJwt;

// Issue token for mobile app (longer TTL)
$mobilePayload = Payload::create(
    uid: 123,
    username: 'john_doe',
    platform: 'app',
    exp: time() + 43200,  // 30 days
    iat: time(),
    jti: uniqid('jwt_')
);
$mobileToken = KodeJwt::guard('app')->issue($mobilePayload);

// Issue token for web (shorter TTL for security)
$webPayload = Payload::create(
    uid: 123,
    username: 'john_doe',
    platform: 'web',
    exp: time() + 1440,  // 24 hours
    iat: time(),
    jti: uniqid('jwt_')
);
$webToken = KodeJwt::guard('web')->issue($webPayload);

// Validate platform-specific token
$payload = KodeJwt::guard('app')->authenticate($mobileToken);
echo $payload->platform;  // 'app'
```

---

## ⚙️ Multi-runtime Support

| Environment | Support | Description |
|-------------|---------|-------------|
| PHP-FPM | ✅ | Uses Redis or database storage for blacklist |
| Swoole Coroutine | ✅ | Uses `Swoole\Coroutine\Redis`, avoids connection leaks |
| RoadRunner | ✅ | Works with `spiral/roadrunner-jobs` for asynchronous cleanup |
| ReactPHP | ⚠️ | Requires asynchronous storage driver adaptation (future plan) |

---

## 🔍 Security and Performance Optimization

- **JTI Anti-replay**: Each Token has a unique `jti`, added to blacklist to prevent replay attacks
- **Platform Isolation**: Tokens from different platforms are not interoperable
- **Signature Security**: Recommended to use `RS256` asymmetric encryption
- **Reflection Cache**: Uses `OpCache` + `ReflectionClass` for cached configuration parsing
- **Memory Optimization**: Avoids large object references, uses `readonly` to reduce copy overhead
- **Sensitive Data Protection**: Supports custom encrypted data fields, users can implement their own encryption/decryption logic
- **Flexible Field Design**: `uid` and `username` fields are optional, supporting string types like snowflake ID
- **Data Minimization**: Only includes necessary fields, reducing Token size and transmission costs

---

## 🧩 Extension Recommendations (IDE Friendly)

### 1. Static Analysis with PHPStan / Psalm

```json
// phpstan.neon
parameters:
    level: 12
    paths:
        - src
```

### 2. IDE Helper (Generate `ide-helper.php`)

```php
// For IDE to recognize static facade
/** @method static \Kode\Jwt\Token\Payload authenticate(string $token) */
/** @method static string issue(\Kode\Jwt\Token\Payload $payload) */
class KodeJwt {}
```

---

## 📈 Future Plans

- [ ] Support JWT multi-signature (Detached Signature)
- [ ] Integrate OpenID Connect support
- [x] Provide CLI tool for Token management, key pair generation (Completed)
- [ ] Support JWT and OAuth2 hybrid mode
- [ ] Provide Prometheus monitoring metrics (Token count, refresh frequency, etc.)
- [ ] Implement JWT key rotation mechanism, supporting smooth transition

---

## 🤝 Contribution and Feedback

Welcome to submit Issues or PRs!  
GitHub: `https://github.com/kode-php/jwt`

---

> **Naming Principle**: Avoid conflicts with PHP native `jwt_*` functions, use `KodeJwt` prefix, class names clearly express responsibilities, method names start with verbs (`issue`, `authenticate`, `refresh`, `invalidate`).

> **Contravariance/Covariance Example**:  
> `StorageInterface` as a covariant return type, `GuardInterface` can accept more specific `Payload` subclasses (via generic simulation).

---

🎯 **Goal Achieved**:  
A **secure, robust, easy-to-use, high-performance** JWT package suitable for full-scenario requirements from traditional FPM to modern coroutine projects.