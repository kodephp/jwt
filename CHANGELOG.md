# Changelog

所有重要变更都会记录在此文件中。版本遵循 [Semantic Versioning](https://semver.org/)。

## [1.8.1] - 2026-06-03

### Added
- 新增 `Kode\Jwt\Contract\SsoStorageInterface`，提供 SSO 高级能力抽象
  - `atomicRevoke()`：原子化撤销（黑名单 + SSO 映射 + 用户 Token 列表 + Token 详情）
  - `trackUserToken()`：记录到用户活跃 Token 列表（最多保留 50 条）
  - `setSsoMapping()` / `getSsoMapping()`：SSO 平台 → JTI 映射便捷方法
- `RedisStorage` / `MemoryStorage` / `FileStorage` 等存储实现 `SsoStorageInterface` 接口
- `examples/basic_usage.php` 中演示 `expected_claims` 强制校验
- `examples/storage_usage.php` 中演示 `SsoStorageInterface` 增强能力
- `examples/advanced_usage.php` 中演示标准声明（iss/aud/sub/nonce）
- 新增 `tests/SsoStorageInterfaceTest.php` 覆盖 8 个 SSO 增强能力用例
- 新增 `src/Stub/RedisStub.php` 提供 ext-redis 扩展的 IDE 存根

### Changed
- `BaseGuard` 与 `SsoGuard` 从 `method_exists` 探测改为 `instanceof SsoStorageInterface` 探测
- `SsoGuard::isUnique()` 使用原子化撤销（`atomicRevoke`）替代多步操作
- `SsoGuard::register()` 同时写入 SSO 映射 + 用户活跃 Token 列表
- `BaseGuard::getUserActiveTokens()` 支持 `int|string` UID 与可选平台过滤
- `Payload::toArray()` 自动将 `issuer/audience/subject` 映射为标准声明键 `iss/aud/sub`
- `Payload::setEncryptedData()` 在 `readonly` 类下返回新实例而非修改原实例
- 提升 `composer.json` PHP 版本约束至 `^8.2`（`readonly class` 需要 8.2+）

### Fixed
- 修复 `RedisStorage::setMultiple()` 中 `multi()` 可能返回 `false` 时的类型错误
- 修复 `RedisStorage::connect()` 传 `null` 给 `RedisStub::connect()` 的类型不匹配
- 修复 `BaseGuard` 缺少 `array<string, mixed>` 值类型注解导致的 phpstan level 7 错误
- 修复 `SsoGuard` 缺少构造函数值类型注解导致的 phpstan level 7 错误
- 修复 `RedisReplayProtection` 缺少值类型注解导致的 phpstan level 7 错误
- 修复 `Payload::fromArray()` PHPDoc 数组 shape 缺少 `audience/issuer/subject` 别名键
- 修复 `Payload::hasRole()` / `hasPermission()` 表达式右侧恒为真导致的 phpstan 警告
- 修复 `Payload::setEncryptedData()` 在 `readonly` 类上修改属性导致的 phpstan 错误

### Security
- 强化 SSO 撤销语义：使用 Lua 脚本（RedisStorage）保证"黑名单 + SSO + 用户列表"原子性
- 持续使用 32 字节（256 bit）高熵 JTI，远高于 UUID v4

## [1.8.0] - 2025-12-29

### Added
- 初始 v1.8.0 发布
- 支持 SSO 和 MLO 登录模式
- 多种存储驱动支持（Redis、Memory、File、Apcu、Memcached、Database、CoroutineRedis）
- 防重放攻击（Anti-Replay）支持
- 标准声明（iss/aud/sub）支持
- 高熵 JTI（32 字节）
- 时钟漂移容忍（`clock_skew`）
- 多签名 / OAuth2 / OpenID Connect 支持
