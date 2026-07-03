# Changelog

本文件记录 `kode/jwt` 所有版本的显著变更。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

---

## [1.9.0] - 2026-07-04

### 总结

本次发版将最低 PHP 版本提升至 **8.3+**，引入 **JWK 密钥管理模块（RFC 7517）**、**Token 客户端指纹绑定**、**算法白名单三层防御**，并全面应用 PHP 8.3 现代化特性（`readonly class`、类型化类常量、`json_validate()`、`#[\Override]` 属性）。同时修复了 v1.8.2 中遗留的多处 P0/P1 缺陷，新增 31 个测试（145 测试 / 413 断言）。

### Added — 新增功能

- **JWK 密钥管理模块**（`src/Key/`）
  - `Jwk`：`final readonly class` 值对象，符合 RFC 7517，支持 RSA / EC / oct 三种密钥类型
  - `JwkSet`：JWK 集合，用于密钥轮换场景下按 `kid` 选择密钥，支持不可变 `with()` / `without()` 链式操作
  - `KeyConverter`：PEM ↔ JWK 互转，包含 ASN.1 DER 编码实现 RSA SubjectPublicKeyInfo 构造
  - `JwkFactory`：CSPRNG 安全密钥生成（`random_bytes`），RSA 默认 2048 位（NIST SP 800-131A），对称密钥按算法自动选择长度（HS256=32B / HS384=48B / HS512=64B）
- **Token 客户端指纹绑定**（`src/Security/Fingerprint.php`）
  - 将 Token 与客户端 UA + IP 前缀绑定，防止跨设备/跨网络环境重放
  - IP 前缀归一化（IPv4 `/24`、IPv6 `/64`），避免 NAT 网络下频繁切换 IP 导致误判
  - 内置可信内网 IP 白名单（`127.`、`10.`、`192.168.`、`172.16.`~`172.31.`）
  - 常量时间比较（`hash_equals`）防止时序攻击
  - 支持 `ipPrefixOnly` 模式，适配移动端 UA 频繁变化场景
- **算法白名单三层防御**（`Parser::ensureAllowedAlgorithm()`）
  - 防御层 1：永久禁用 `none` 算法
  - 防御层 2：显式白名单（`allowed_algorithms` 数组），适用于密钥轮换、多算法并存
  - 防御层 3：单算法严格匹配（`algo` 单值），防止算法混淆攻击
- **PHP 8.3 现代化特性全面应用**
  - `readonly class`：`Jwk`、`JwkSet` 整类不可变
  - 类型化类常量：`private const array SUPPORTED_KTY = [...]` 等
  - `json_validate()`：替代 `json_decode` + `json_last_error` 检查
  - `#[\Override]` 属性：显式声明方法重写
- **测试套件扩充**
  - `tests/JwkTest.php`：19 个测试，覆盖 Jwk 创建/序列化、kty 归一化、toPublic、fromArray/fromJson 往返、computeKid 确定性、JwkSet 操作、工厂密钥生成、RSA 与 openssl_sign/verify 端到端验证
  - `tests/FingerprintTest.php`：12 个测试，覆盖相同上下文相同哈希、不同 UA/IP 不同哈希、IP 前缀归一化、verify 匹配/失配、可信内网 IP 跳过、ensureMatch 异常、IPv6 支持、ipPrefixOnly 禁用选项
  - 回归测试：`testQuickCreateDoesNotOverrideTtlWithRefreshTtl`、`testTtlUnitSecondsIsRespected`、`testRefreshDoesNotDoubleParseToken`

### Changed — 变更

- **composer.json**：`php` 约束从 `^8.2` 提升至 `^8.3`
- **composer.json**：`version` 从 `1.8.2` 升至 `1.9.0`
- **composer.json**：新增 keywords `jwk`、`php83`、`php84`、`fingerprint`
- **存储 `set()` 默认 TTL 统一为 0**：所有存储驱动 `set(string $key, mixed $value, int $ttl = 0): bool` 语义一致，0 表示永不过期
- **`BaseGuard` 支持 `ttl_unit` / `refresh_ttl_unit` 配置**：兼容 `seconds` / `minutes` / `hours`，默认 `minutes`
- **`Parser` / `Builder` 公私钥缓存**：按文件路径 + mtime 缓存读取内容，按内容 md5 缓存解析后的 OpenSSLAsymmetricKey，避免重复 IO 与解析
- **`KeyRotationManager::getAllKeys` 优化**：使用 `getMultiple()` 批量获取，消除 N+1 查询
- **`BaseGuard::refresh` 优化**：提取 `canRefreshPayload(Payload)` 内部方法，避免二次解析 Token

### Fixed — 修复

- **`Payload::quickCreate` 语义错误**：不再用 `refresh_ttl` 覆盖 `ttl`，避免 TTL 配置失效（P0）
- **`MultiSignature::findSigner` 验证失败**：默认 keyId 与 `sign()` 一致（`signer_{index}`），修复多签验证失败问题（P0）
- **`RedisStorage::getRemainingTtl` TTL 误报**：永不过期的 Key 返回 -1 而非误报 TTL（P0）
- **`CoroutineRedisStorage::getRemainingTtl` 同步修复**：与 `RedisStorage` 保持一致
- **`CoroutineRedisStorage::setMultiple` 类型错误**：修复 `foreach` 作用于 `false` 的致命错误
- **`ApcuStorage::set` 写入逻辑**：主 Key 写入失败时不再写入 `meta_ttl`，避免脏数据
- **`ApcuStorage::delete` 清理遗漏**：删除主 Key 时同步清理 `meta_ttl` 元数据键
- **`FileStorage` key 碰撞**：文件路径增加 sha256 短哈希前缀，避免长 key 名被截断后碰撞
- **`FileStorage::cleanExpired` 返回类型**：明确为 `int|false`，与接口契约一致
- **`KodeJwt::tokenManager` 守卫选择**：统一使用 `$guardName`，避免在多守卫场景下错误复用默认守卫

### Removed — 移除

- **移除 `src/Stub/RedisStub.php`**：移除通过 `autoload.files` 全局别名化 `Redis` 类的反模式，改为运行时检测扩展加载
- **移除 `composer.json` 中的 `autoload.files`**：不再全局注入 stub 文件
- **移除弱随机 fallback**：`AntiReplay::generateNonce()` 在 `random_bytes` 失败时直接抛异常，不再降级到 `mt_rand`

### Security — 安全

- **算法混淆攻击防御**：通过 `Parser::ensureAllowedAlgorithm()` 三层防御，杜绝 `alg=none` 攻击、`HS256/RS256` 混淆攻击
- **JWK 私钥隔离**：`Jwk::toPublic()` 返回新实例（剥离 `d/p/q/dp/dq/qi/k` 等私钥参数），原对象仍可继续用于签发；`__toString()` 脱敏输出
- **RSA 密钥长度强制**：`JwkFactory::generateRsaKeyPair()` 强制最低 2048 位（NIST SP 800-131A）
- **CSPRNG 密钥生成**：所有密钥生成使用 `random_bytes()`，不使用 `mt_rand` / `rand`

### Deprecations — 弃用

无新增弃用项。

### Breaking Changes — 不兼容变更

- **最低 PHP 版本**：从 8.2 提升至 8.3
- **存储 `set()` 默认 TTL**：从各自默认值统一为 0（永不过期），调用方若依赖原默认值需显式传入 TTL

---

## [1.8.2] - 2026-07-03

### Added

- **存储驱动接口补齐**：`ApcuStorage`、`DatabaseStorage`、`CoroutineRedisStorage`、`MemcachedStorage` 补齐 `touch` / `getRemainingTtl` / `clear` 方法，并实现 `SsoStorageInterface`
- **`SsoStorageInterface` 能力探测**：业务代码通过 `instanceof` 自动使用高级 API，缺失时降级为通用实现
- **DatabaseStorage SQL 方言自动适配**：根据 DSN 自动检测 MySQL / SQLite 驱动类型，使用对应方言

### Changed

- **TokenManager N+1 查询修复**：`getUserTokens()` 改用 `getMultiple()` 批量获取
- **Parser RSA 公钥缓存**：`verifyRsa()` 缓存已解析的公钥资源，避免重复磁盘 IO
- **DatabaseStorage 概率清理**：读操作中 `cleanExpired()` 改为 1% 概率触发
- **FileStorage 紧凑 JSON**：`set()` / `touch()` 移除 `JSON_PRETTY_PRINT`
- **FileStorage 共享锁读取**：`get()` / `has()` 改用 `flock(LOCK_SH)` 读取
- 全局 `declare(strict_types=1)` 补齐

### Fixed

- **MemcachedStorage `addServers` 参数结构 Bug**：配置中的关联数组现在会自动转换为索引数组

### Security

- **移除弱密钥默认值**：`KodeJwt::getDefaultConfig()` 中 `secret` 改为空字符串，强制用户配置
- **移除伪随机 fallback**：`AntiReplay::generateNonce()` 在 `random_bytes` 失败时抛异常
- **DatabaseStorage 表名注入防护**：构造函数中用正则校验表名
- **DatabaseStorage PDO 安全选项**：强制 `ATTR_EMULATE_PREPARES = false`
- **CoroutineRedisStorage 惰性加载**：移除顶部 `use Swoole\Coroutine\Redis` 硬依赖

---

## [1.8.1] - 2026-07-02

### Added

- **`Kode\Jwt\Contract\SsoStorageInterface`**：用于描述存储后端的"高级 SSO 能力"
  - `atomicRevoke()`：原子化撤销（黑名单 + SSO 清理 + 用户列表清理 + 详情清理）
  - `trackUserToken()`：记录到用户活跃 Token 列表（最多保留 50 条）
  - `setSsoMapping()` / `getSsoMapping()`：SSO 平台 → JTI 映射

### Changed

- **`Payload` 改为 `readonly` 类**：`setEncryptedData()` 改为返回新实例而非修改原实例

---

## [1.8.0] - 2026-07-01

### Added

- **防重放攻击（Anti-Replay）**：基于 Redis Nonce + 滑动窗口
- **高熵 JTI**：32 字节（256 bit）密码学安全随机数
- **标准声明（iss / aud / sub）**：业务级强制校验
- **时钟漂移容忍**：`clock_skew` 配置
- **Redis 原子化撤销**：Lua 脚本保证"黑名单 + SSO 映射 + 用户 Token 列表"三步原子性

---

## [1.7.0] - 2026-06-15

### Added

- 多平台支持（H5 / PC / App / 小程序）
- SSO 单点登录 + MLO 多点登录
- Token 黑名单机制
- 自动续期（Refresh）
- 事件系统（`TokenIssued`、`TokenExpired`、`TokenRevoked` 等）
- 多存储驱动（Redis、Memory、File、Apcu、Database、Memcached）
- OpenID Connect 支持
- OAuth2 混合模式
- JWT 多签（Detached Signature）
- 密钥轮换机制（`KeyRotationManager`）
- Prometheus 监控指标
- CLI 工具（`bin/jwt`）

---

[1.9.0]: https://github.com/kode-php/jwt/releases/tag/v1.9.0
[1.8.2]: https://github.com/kode-php/jwt/releases/tag/v1.8.2
[1.8.1]: https://github.com/kode-php/jwt/releases/tag/v1.8.1
[1.8.0]: https://github.com/kode-php/jwt/releases/tag/v1.8.0
[1.7.0]: https://github.com/kode-php/jwt/releases/tag/v1.7.0
