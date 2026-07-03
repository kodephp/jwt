# Changelog

本文件记录 `kode/jwt` 所有版本的显著变更。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

---

## [1.10.0] - 2026-07-04

### 总结

本次发版聚焦 **OAuth2 / OIDC 互操作能力增强**，新增四个 RFC 标准模块：JWKS 端点发布（RFC 7517 §5）、Token Introspection（RFC 7662）、OIDC Discovery（RFC 8414）、Scope 值对象与声明检查器。同时引入 `TokenPolicy` 策略对象统一管理 Token 校验逻辑，并在 `KodeJwt` 门面层暴露 `introspect / jwks / discovery / tokenPolicy / claimInspector / scope` 便捷方法。测试套件扩展至 246 个测试 / 610 个断言。

### Added — 新增功能

- **JWKS 端点发布模块**（`src/OAuth2/JwksPublisher.php` + `JwksResponse.php`）
  - `JwksPublisher`：将本地 JWK Set 以 RFC 7517 §5 标准 JSON 格式发布到 `jwks_uri`
  - 自动调用 `JwkSet::toPublic()` 剥离私钥参数，杜绝私钥泄露
  - 提供强 ETag（基于公开 JWK Set JSON 的 sha256）与 `Cache-Control` 头
  - 支持 `If-None-Match` 协商缓存（304 Not Modified），含弱 ETag 与通配符 `*` 匹配
  - `JwksResponse`：与 PSR-7 / PSR-15 解耦的响应值对象（status / headers / body）
- **Token Introspection 模块**（`src/OAuth2/IntrospectionResponse.php` + `Introspector.php`）
  - `IntrospectionResponse`：RFC 7662 §2.2 响应值对象，`final readonly class`
    - 包含全部标准字段：active / scope / client_id / username / token_type / exp / iat / nbf / sub / aud / iss / jti
    - `fromPayload()` 工厂：从 `Payload` 构造 active=true 响应
    - `inactive()` 工厂：构造 active=false 响应（仅 `{"active":false}`）
    - 实现 `Arrayable` / `Jsonable` 双向序列化
  - `Introspector`：内省服务
    - `introspect(token)` 自动完成解析验签 + 黑名单检查
    - 任何异常（格式错误、签名错误、过期、黑名单）统一返回 `active=false`，不泄露失败原因
    - 支持 `fromPayload()`：基于已校验 Payload 直接构造响应
- **OIDC Discovery 模块**（`src/OpenId/DiscoveryConfiguration.php` + `DiscoveryPublisher.php`）
  - `DiscoveryConfiguration`：RFC 8414 元数据值对象
    - 必填字段：issuer / authorization_endpoint / token_endpoint / jwks_uri
    - 可选字段：userinfo_endpoint / introspection_endpoint / revocation_endpoint / end_session_endpoint
    - 默认值：scopes_supported / response_types_supported / grant_types_supported / subject_types_supported / id_token_signing_alg_values_supported / claims_supported
    - 支持 `extra` 字段扩展（如 require_auth_time、code_challenge_methods_supported）
  - `DiscoveryPublisher`：Discovery 端点发布器
    - 标准 OIDC 路径：`/.well-known/openid-configuration`
    - 标准 OAuth2 路径：`/.well-known/oauth-authorization-server`
    - 同样支持 ETag / If-None-Match 协商缓存
- **Scope 值对象**（`src/Claim/Scope.php`）
  - 不可变集合语义（`final readonly class`），实现 `Arrayable` / `Jsonable` / `\Countable`
  - 多种工厂：`fromString()`（空格分隔）/ `fromArray()` / `fromJson()`
  - 集合运算：`has()` / `hasAny()` / `hasAll()` / `intersect()` / `diff()` / `merge()`
  - 校验：`allAllowed()` / `allStandard()`（OIDC 标准 scope 检查）
  - 字符合法性校验：拒绝控制字符与重复 scope（去重）
  - 支持 `__toString()` 魔法方法，方便直接嵌入 Token
- **Claim 声明检查器**（`src/Claim/ClaimInspector.php`）
  - 纯无状态服务，统一处理声明校验逻辑
  - 校验项：`assertIssuer` / `assertAudience` / `assertSubject` / `assertTimeWindow` / `assertScopesAll` / `assertScopesAny` / `assertCustomEquals` / `assertPlatform`
  - 时间窗口含 `exp` / `nbf` / `iat` 校验，支持时钟漂移容忍
  - 全部失败抛出 `TokenInvalidException`，携带 `jti` 便于排查
  - 链式调用：`$inspector->assertIssuer(...)->assertAudience(...)->assertScopesAll(...)`
- **TokenPolicy 策略对象**（`src/Policy/TokenPolicy.php`）
  - 不可变值对象（`final readonly class`），承载完整 Token 校验策略
  - 链式 with* 方法：`withIssuer` / `withAudience` / `withPlatform` / `withRequiredScopes` / `withAnyScopes` / `withRequiredCustom` / `withClockSkew` / `withIgnoreExpiration`
  - `enforce(Payload)` 一次性执行全部策略，失败抛异常
  - `satisfies(Payload)` 不抛异常的判定版本
  - `extractAllowedScope(Payload)` 提取命中 scope 集合
  - `fromArray()` / `toArray()` 序列化支持
- **KodeJwt 门面新增便捷方法**
  - `KodeJwt::jwksPublisher(JwkSet, maxAge)`：创建 JWKS 端点发布器
  - `KodeJwt::introspector(guard)`：创建 Introspector
  - `KodeJwt::introspect(token, expectedPlatform, clientId, guard)`：便捷内省
  - `KodeJwt::discoveryConfiguration(issuer, ...)`：创建 Discovery 配置
  - `KodeJwt::discoveryPublisher(config, maxAge)`：创建 Discovery 端点发布器
  - `KodeJwt::tokenPolicy()`：创建空 Token 策略
  - `KodeJwt::claimInspector()`：创建 Claim 检查器
  - `KodeJwt::scope(string)`：从字符串创建 Scope 值对象
- **测试套件扩充**
  - `tests/JwksEndpointTest.php`：18 个测试，覆盖 JSON 输出 / ETag 稳定性 / Cache-Control / 304 协商缓存 / 弱 ETag / 通配符
  - `tests/IntrospectionTest.php`：16 个测试，覆盖 active/inactive 响应 / Introspector 有效/无效/过期/黑名单/平台不匹配/签名错误
  - `tests/DiscoveryTest.php`：18 个测试，覆盖必填字段 / 可选字段 / extra / fromArray / fromJson / Publisher 协商缓存
  - `tests/ScopeTest.php`：11 个测试，覆盖 fromString / fromArray / has / 集合运算 / 白名单 / JSON
  - `tests/ClaimInspectorTest.php`：22 个测试，覆盖 issuer / audience / subject / 时间窗口 / scope / custom / platform / 链式
  - `tests/TokenPolicyTest.php`：19 个测试，覆盖链式构造 / enforce / satisfies / extractAllowedScope / toArray / fromArray

### Changed — 变更

- **composer.json**：`version` 从 `1.9.0` 升至 `1.10.0`
- **composer.json**：新增 keywords `jwks`、`openid`、`openid-connect`、`introspection`、`discovery`
- **`KodeJwt` 门面扩展**：新增 8 个便捷方法，覆盖 JWKS / Introspection / Discovery / Policy / Scope

### Fixed — 修复

无新增修复（v1.9.0 已修复全部已知 P0/P1 缺陷）。

### Security — 安全

- **Introspector 信息侧通道防御**：任何失败统一返回 `active=false`，不向资源服务器泄露失败原因
- **JWKS 端点私钥隔离**：`JwksPublisher` 永远只输出公开 JWK Set
- **Scope 字符合法性校验**：拒绝控制字符与非法字符，避免 scope 注入
- **ClaimInspector 常量时间比较**：issuer / platform / subject 使用 `hash_equals` 防止时序攻击

### Deprecations — 弃用

无新增弃用项。

### Breaking Changes — 不兼容变更

无新增不兼容变更（v1.10.0 为向下兼容的功能增强版本）。

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

[1.10.0]: https://github.com/kode-php/jwt/releases/tag/v1.10.0
[1.9.0]: https://github.com/kode-php/jwt/releases/tag/v1.9.0
[1.8.2]: https://github.com/kode-php/jwt/releases/tag/v1.8.2
[1.8.1]: https://github.com/kode-php/jwt/releases/tag/v1.8.1
[1.8.0]: https://github.com/kode-php/jwt/releases/tag/v1.8.0
[1.7.0]: https://github.com/kode-php/jwt/releases/tag/v1.7.0
