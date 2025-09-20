# Kode JWT

A robust, comprehensive, and modern PHP 8.1+ JWT package with support for Single Sign-On (SSO), Multi-Login (MLO), blacklist management, auto-refresh, and multi-platform adaptation.

## Features

- ✅ **Native PHP 8.1+ Support**: Utilizes modern PHP features like `readonly` properties, `enum`, `never` type, etc.
- ✅ **Multi-Platform Support**: H5, PC, App, Mini Programs (WeChat/Alipay/Douyin), etc.
- ✅ **Single Sign-On (SSO)**: Only one valid token per user per platform
- ✅ **Multi-Login (MLO)**: Support multiple simultaneous logins for the same user
- ✅ **Token Blacklist**: Support for active logout and forced offline
- ✅ **Auto-Refresh**: Support for sliding expiration and fixed refresh cycles
- ✅ **Multi-Environment Configuration**: Support for `config/jwt.php` configuration
- ✅ **Runtime Compatibility**: Support for FPM, Swoole (multi-process/coroutine), RoadRunner
- ✅ **Type Safety & Reflection Optimization**: High-performance dependency injection and configuration parsing
- ✅ **Zero Framework Dependency**: Can be used independently or integrated with any framework
- ✅ **Event-Driven**: Provides event hooks like `TokenIssued`, `TokenExpired`, `TokenRevoked`
- ✅ **Pluggable Encryption Algorithms**: Default `HS256` / `RS256`, supports custom signers

## Installation

```bash
composer require kode/jwt
```

## Configuration

Create a `config/jwt.php` file:

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
            'refresh_ttl' => 20160,      // minutes (2 weeks)
            'ttl' => 1440,               // minutes (24 hours)
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
            'limit' => 10000, // Maximum cache size
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

## Usage

## Payload Class Detailed Usage

The Payload class provides flexible ways to handle custom data and enhanced methods for working with JWT payloads.

### Flexible Custom Data Handling

The Payload class offers two ways to handle custom data:

#### Using the `create()` Static Method (Recommended)

```php
// 1. Using array custom data
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
    exp: time() + 3600,
    iat: time(),
    jti: uniqid('jwt_'),
    roles: ['user'],
    perms: ['read'],
    customData: $encryptedData
);
```

#### Using the `fromArray()` Method

```php
// Create a Payload from an array (includes required field validation)
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
        'location' => 'New York'
    ]
];

$payload = Payload::fromArray($data);
```

### Enhanced Methods Implementation

The Payload class provides rich methods for manipulating and checking payload data:

#### Custom Data Operations

```php
// Get all custom data
$customData = $payload->getCustomData();

// Get specific custom data
$department = $payload->getCustom('department', 'Unknown');

// Check if specific custom data exists
if ($payload->hasCustom('department')) {
    echo "Department: " . $payload->getCustom('department');
}

// Get encrypted custom data
$encryptedData = $payload->getEncryptedData();

// Check if encrypted custom data exists
if ($payload->hasEncryptedData()) {
    $data = json_decode(base64_decode($encryptedData), true);
    // Process decrypted data
}
```

#### Role and Permission Checking

```php
// Check if user has a specific role (using strict comparison)
if ($payload->hasRole('admin')) {
    // User has admin role
}

// Check if user has a specific permission (using strict comparison)
if ($payload->hasPermission('delete')) {
    // User has delete permission
}
```

#### Other Utility Methods

```php
// Get user information
$userInfo = $payload->getUserInfo();

// Check if token has expired
if ($payload->isExpired()) {
    // Token has expired
}

// Get remaining time to live
$ttl = $payload->getTtl();

// Get user identifier
$userIdentifier = $payload->getUserIdentifier();
```

### 1. Issuing a Token

```php
use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

// Initialize the package with configuration
KodeJwt::init(require 'config/jwt.php');

$payload = Payload::create(
    uid: 123,
    username: 'john_doe',
    platform: 'app',
    exp: time() + 1440 * 60,  // 24 hours
    iat: time(),
    jti: uniqid('jwt_', true),
    roles: ['user'],
    perms: ['read', 'write']
);

$token = KodeJwt::issue($payload);

// Returns: ['token' => 'eyJ...', 'expires_in' => 1440, 'refresh_ttl' => 20160]
```

### 2. Authenticating a Token

```php
try {
    $payload = KodeJwt::authenticate($token);
    echo $payload->username; // john_doe
} catch (TokenInvalidException $e) {
    // Handle invalid token
} catch (TokenExpiredException $e) {
    // Handle expired token
} catch (TokenBlacklistedException $e) {
    // Handle blacklisted token
}
```

### 3. Refreshing a Token

```php
try {
    $newToken = KodeJwt::refresh($oldToken);
} catch (TokenInvalidException $e) {
    // Handle invalid token
} catch (TokenExpiredException $e) {
    // Handle expired token (cannot be refreshed)
}
```

### 4. Invalidating a Token (Adding to Blacklist)

```php
KodeJwt::invalidate($token);
```

## Storage Drivers

The package supports multiple storage drivers:

- **Redis**: For distributed applications
- **Memory**: For single-process applications
- **Database**: For persistent storage
- **File**: For simple file-based storage
- **APCu**: For shared memory storage
- **Memcached**: For distributed memory storage
- **Null**: For testing purposes (no storage)

## Runtime Support

| Environment | Support | Notes |
|-------------|---------|-------|
| PHP-FPM | ✅ | Uses Redis or database for blacklist storage |
| Swoole Coroutine | ✅ | Uses `Swoole\Coroutine\Redis`, avoids connection leaks |
| RoadRunner | ✅ | Works with `spiral/roadrunner-jobs` for async cleanup |
| ReactPHP | ⚠️ | Requires async storage drivers (planned) |

## Security & Performance Optimizations

- **JTI Anti-Replay**: Each token has a unique `jti`, added to blacklist to prevent replay attacks
- **Platform Isolation**: Tokens from different platforms are not interoperable
- **Signature Security**: Recommends using `RS256` asymmetric encryption
- **Reflection Caching**: Uses `OpCache` + `ReflectionClass` to cache configuration parsing
- **Memory Optimization**: Avoids large object references, uses `readonly` to reduce copy overhead

## Extensibility

### 1. Using PHPStan / Psalm for Static Analysis

```json
// phpstan.neon
parameters:
    level: 12
    paths:
        - src
```

### 2. IDE Helper (Generate `ide-helper.php`)

```php
// For IDE recognition of static facade
/** @method static \Kode\Jwt\Token\Payload authenticate(string $token) */
/** @method static string issue(\Kode\Jwt\Token\Payload $payload) */
class KodeJwt {}
```

## Future Plans

- [ ] Support JWT detached signature
- [ ] Integrate OpenID Connect support
- [ ] Provide CLI tools for token management and key pair generation
- [ ] Support JWT and OAuth2 hybrid mode
- [ ] Provide Prometheus monitoring metrics (token count, refresh frequency, etc.)

## Contributing

Contributions are welcome! Please submit issues or PRs.