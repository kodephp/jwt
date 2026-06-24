# Changelog

所有重要变更都会记录在此文件中。版本遵循 [Semantic Versioning](https://semver.org/)。

## [1.8.2] - 2026-06-03

### Added
- 补齐 `ApcuStorage` 的 `touch`/`getRemainingTtl`/`clear` 方法（原缺失会导致致命错误）
- 补齐 `DatabaseStorage` 的 `touch`/`getRemainingTtl`/`clear` 方法
- 补齐 `CoroutineRedisStorage` 的 `touch`/`getRemainingTtl`/`clear` 方法
- 补齐 `MemcachedStorage` 的 `touch`/`getRemainingTtl`/`clear` 方法
- `ApcuStorage`/`DatabaseStorage`/`CoroutineRedisStorage`/`MemcachedStorage` 实现 `SsoStorageInterface`
- `DatabaseStorage` SQL 方言自动适配（SQLite / MySQL）
- `Parser` RSA 公钥缓存（避免重复磁盘 IO 与密钥解析）
- `FileStorage` 共享锁读取（`flock(LOCK_SH)`），与写入的 `LOCK_EX` 对称
- `CoroutineRedisStorage` 惰性加载 Swoole 扩展，移除顶部硬依赖
- `DatabaseStorage` 表名正则校验，防止 SQL 注入
- `DatabaseStorage` 强制 `PDO::ATTR_EMULATE_PREPARES = false`

### Changed
- `TokenManager::getUserTokens()` 改用 `getMultiple()` 批量获取，修复 N+1 查询
- `TokenManager::revokeUserTokens()` 抽取重复逻辑为 `revokeTokensFromList()`
- `TokenManager::isTokenValid()` 异常捕获从 `\Exception` 收窄为 `JwtException`
- `TokenManager::cleanExpiredTokens()` 保留存储驱动返回的实际清理数量
- `DatabaseStorage` 读操作中 `cleanExpired()` 改为 1% 概率触发
- `FileStorage::set()`/`touch()` 移除 `JSON_PRETTY_PRINT`，使用紧凑格式
- `KodeJwt::getDefaultConfig()` 中 `secret` 改为空字符串，强制用户配置
- `NullStorage::getRemainingTtl()` 返回值从 -1 修正为 -2（键不存在）

### Fixed
- 修复 `MemcachedStorage::addServers()` 参数结构 Bug（关联数组未转换为索引数组）
- 修复 `MemcachedStorage::get()` 仅检查 `RES_NOTFOUND` 导致其他错误码返回脏数据
- 修复 `CoroutineRedisStorage` 顶部 `use Swoole\Coroutine\Redis` 硬依赖导致未安装时类加载失败
- 修复 `CoroutineRedisStorage::connect()` 中 `auth`/`select` 返回值未检查
- 修复 `DatabaseStorage` 硬编码 SQLite 方言与 MySQL 默认配置冲突
- 修复 `DatabaseStorage::getStats()` 中 `query()` 返回 `false` 时调用 `fetchColumn()` 致命错误
- 修复 `AntiReplay::generateNonce()` 伪随机 fallback 安全隐患
- 修复 `FileStorage::mkdir()` 失败未检查
- 修复 `StorageFactory` Swoole 协程检测硬编码 `\Swoole\Coroutine::getCid()`
- 修复 `StorageFactory` 异常类型过宽（`\Exception` → `\InvalidArgumentException`）

### Security
- 移除 `KodeJwt` 默认配置中的弱密钥 `'your-256-bit-secret-key-here'`
- 移除 `AntiReplay::generateNonce()` 不安全的伪随机 fallback
- `DatabaseStorage` 表名正则校验防止 SQL 注入
- `DatabaseStorage` 强制 `PDO::ATTR_EMULATE_PREPARES = false`

## [1.8.1] - 2026-06-03

### Added
- 新增 `Kode\Jwt\Contract\SsoStorageInterface`，提供 SSO 高级能力抽象
- `RedisStorage` / `MemoryStorage` / `FileStorage` 等存储实现 `SsoStorageInterface` 接口
- `examples/` 中演示 `expected_claims` 强制校验、`SsoStorageInterface` 增强、标准声明
- 新增 `tests/SsoStorageInterfaceTest.php` 覆盖 8 个 SSO 增强能力用例
- 新增 `src/Stub/RedisStub.php` 提供 ext-redis 扩展的 IDE 存根

### Changed
- `BaseGuard` 与 `SsoGuard` 从 `method_exists` 探测改为 `instanceof SsoStorageInterface` 探测
- `Payload::toArray()` 自动将 `issuer/audience/subject` 映射为标准声明键 `iss/aud/sub`
- `Payload::setEncryptedData()` 在 `readonly` 类下返回新实例
- 提升 `composer.json` PHP 版本约束至 `^8.2`

### Fixed
- 修复 `RedisStorage::setMultiple()` 中 `multi()` 返回 `false` 时的类型错误
- 修复 `BaseGuard`/`SsoGuard`/`RedisReplayProtection` 缺少值类型注解
- 修复 `Payload::hasRole()`/`hasPermission()` 表达式恒为真
- 修复 `Payload::setEncryptedData()` 在 `readonly` 类上修改属性

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
