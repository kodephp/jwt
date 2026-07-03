<?php

declare(strict_types=1);

namespace Kode\Jwt\Guard;

use Kode\Jwt\Contract\GuardInterface;
use Kode\Jwt\Contract\LoggerInterface;
use Kode\Jwt\Contract\SsoStorageInterface;
use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Parser;
use Kode\Jwt\Token\Payload;
use Kode\Jwt\Event\EventDispatcher;
use Kode\Jwt\Event\TokenIssued;
use Kode\Jwt\Event\TokenRefreshed;
use Kode\Jwt\Event\TokenRevoked;
use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Exception\TokenBlacklistedException;
use Kode\Jwt\Exception\TokenInvalidException;
use Kode\Jwt\Exception\TokenReplayException;
use Kode\Jwt\Log\NullLogger;
use Kode\Jwt\Security\AntiReplay;

abstract class BaseGuard implements GuardInterface
{
    protected StorageInterface $storage;
    protected Builder $builder;
    protected Parser $parser;
    protected EventDispatcher $eventDispatcher;
    protected LoggerInterface $logger;

    /** @var array<string, mixed> 守卫配置 */
    protected array $config;

    protected ?AntiReplay $antiReplay = null;

    /**
     * 构造函数
     *
     * @param array<string, mixed> $config 守卫配置
     */
    public function __construct(
        StorageInterface $storage,
        Builder $builder,
        Parser $parser,
        EventDispatcher $eventDispatcher,
        ?LoggerInterface $logger = null,
        array $config = []
    ) {
        $this->storage = $storage;
        $this->builder = $builder;
        $this->parser = $parser;
        $this->eventDispatcher = $eventDispatcher;
        $this->logger = $logger ?? new NullLogger();
        $this->config = $config;
    }

    /**
     * 注入防重放保护器
     */
    public function withAntiReplay(AntiReplay $antiReplay): self
    {
        $this->antiReplay = $antiReplay;
        return $this;
    }

    /**
     * 验证Token
     */
    public function authenticate(string $token): Payload
    {
        try {
            $payload = $this->parser->parse(
                $token,
                $this->getExpectedPlatform(),
                false,
                (array) ($this->config['expected_claims'] ?? [])
            );

            if ($this->storage->isBlacklisted($payload->jti)) {
                $this->logger->warning('Token 在黑名单中，认证失败', ['jti' => $payload->jti]);
                throw new TokenBlacklistedException(jti: $payload->jti, token: $token);
            }

            // 防重放校验
            $this->checkAntiReplay($payload, $token);

            $this->logger->debug('Token 认证成功', ['jti' => $payload->jti, 'platform' => $payload->platform]);
            return $payload;
        } catch (JwtException $exception) {
            $this->logger->error('Token 认证异常', [
                'error' => $exception->getMessage(),
                'jti' => $exception->getJti(),
            ]);
            throw $exception;
        }
    }

    /**
     * 签发Token
     */
    public function issue(Payload $payload): array
    {
        try {
            $uid = $this->normalizeUid($payload->uid);
            $platform = $this->normalizePlatform($payload->platform);

            if (!$this->isUnique($uid, $platform)) {
                throw new JwtException('Token is not unique for this user and platform');
            }

            $token = $this->builder
                ->fromArrayable($payload)
                ->build();

            $this->storeToken($payload, $token);

            $event = new TokenIssued(
                $payload,
                $token,
                $payload->exp - time(),
                $this->getRefreshTtlSeconds(),
                new \DateTimeImmutable()
            );
            $this->eventDispatcher->dispatch($event);

            $this->register($uid, $platform, $payload->jti);
            $this->logger->info('Token 签发成功', ['uid' => $uid, 'platform' => $platform, 'jti' => $payload->jti]);

            return [
                'token' => $token,
                'expires_in' => $payload->exp - time(),
                'refresh_ttl' => $this->getRefreshTtlSeconds()
            ];
        } catch (JwtException $exception) {
            $this->logger->error('Token 签发失败', ['error' => $exception->getMessage()]);
            throw $exception;
        }
    }

    /**
     * 刷新Token
     */
    public function refresh(string $token): array
    {
        // 一次性解析 token，避免在 canRefresh 内重复解析（包含签名验证等重计算）
        try {
            $oldPayload = $this->parser->parse(
                $token,
                $this->getExpectedPlatform(),
                true,
                (array) ($this->config['expected_claims'] ?? [])
            );
        } catch (JwtException $e) {
            $this->logger->error('Token 刷新失败：解析异常', ['error' => $e->getMessage()]);
            throw $e;
        }

        // 基于已解析的 Payload 判断可刷新性，避免再次 parse
        if (!$this->canRefreshPayload($oldPayload)) {
            throw new JwtException('Token cannot be refreshed');
        }

        // 创建新的Payload
        $now = time();
        $newPayload = new Payload(
            uid: $oldPayload->uid,
            username: $oldPayload->username,
            platform: $oldPayload->platform,
            exp: $now + $this->getTtlSeconds(),
            iat: $now,
            jti: self::generateJti(),
            roles: $oldPayload->roles,
            perms: $oldPayload->perms,
            custom: $oldPayload->custom
        );

        // 构建新Token
        $newToken = $this->builder
            ->fromArrayable($newPayload)
            ->build();

        // 将旧Token加入黑名单
        $this->invalidate($token);

        // 存储新Token信息
        $this->storeToken($newPayload, $newToken);

        // 派发事件
        $event = new TokenRefreshed(
            $oldPayload,
            $newPayload,
            $token,
            $newToken,
            new \DateTimeImmutable()
        );
        $this->eventDispatcher->dispatch($event);

        // 注册新Token（由子类实现）
        $newUid = $this->normalizeUid($newPayload->uid);
        $newPlatform = $this->normalizePlatform($newPayload->platform);
        $this->register($newUid, $newPlatform, $newPayload->jti);
        $this->logger->info('Token 刷新成功', ['uid' => $newUid, 'platform' => $newPlatform, 'jti' => $newPayload->jti]);

        return [
            'token' => $newToken,
            'expires_in' => $newPayload->exp - time(),
            'refresh_ttl' => $this->getRefreshTtlSeconds()
        ];
    }

    /**
     * 注销Token
     */
    public function invalidate(string $token): bool
    {
        try {
            $payload = $this->parser->parse(
                $token,
                $this->getExpectedPlatform(),
                true,
                (array) ($this->config['expected_claims'] ?? [])
            );
            $blacklistTtl = $this->getBlacklistTtlSeconds($payload);
            $result = $this->storage->blacklist($payload->jti, $blacklistTtl);

            if ($result) {
                // 派发事件
                $event = new TokenRevoked(
                    $payload,
                    $token,
                    $payload->jti,
                    new \DateTimeImmutable(),
                    'Token invalidated by user'
                );
                $this->eventDispatcher->dispatch($event);
            }

            return $result;
        } catch (TokenInvalidException $e) {
            $this->logger->warning('Token 注销失败，原因是 Token 无效', ['error' => $e->getMessage()]);
            return false;
        }
    }

    /**
     * 检查Token是否可以刷新
     *
     * 兼容外部调用：内部会重新解析 token。Guard 内部刷新流程应使用 canRefreshPayload 避免重复解析。
     */
    protected function canRefresh(string $token): bool
    {
        // 检查是否启用刷新
        if (!($this->config['refresh_enabled'] ?? false)) {
            return false;
        }

        try {
            $payload = $this->parser->parse(
                $token,
                $this->getExpectedPlatform(),
                true,
                (array) ($this->config['expected_claims'] ?? [])
            );

            return $this->canRefreshPayload($payload);
        } catch (TokenInvalidException) {
            return false;
        }
    }

    /**
     * 基于已解析的 Payload 判断是否可刷新
     *
     * 与 canRefresh() 共享同一套规则，但跳过重复解析，供 refresh() 复用。
     */
    protected function canRefreshPayload(Payload $payload): bool
    {
        // 检查是否启用刷新
        if (!($this->config['refresh_enabled'] ?? false)) {
            return false;
        }

        // 检查是否在黑名单中
        if ($this->storage->isBlacklisted($payload->jti)) {
            return false;
        }

        // 检查是否在刷新窗口期内
        $refreshWindow = $payload->exp + $this->getRefreshTtlSeconds();
        return time() <= $refreshWindow;
    }

    protected function getExpectedPlatform(): ?string
    {
        $platform = $this->config['platform'] ?? null;
        if ($platform === null) {
            return null;
        }

        $platform = (string) $platform;
        return $platform === '' ? null : $platform;
    }

    protected function normalizeUid(int|string|null $uid): string
    {
        if ($uid === null || $uid === '') {
            throw new JwtException('User ID (uid) is required');
        }

        return (string) $uid;
    }

    protected function normalizePlatform(string $platform): string
    {
        $platform = trim($platform);
        if ($platform === '') {
            throw new JwtException('Platform is required');
        }

        return $platform;
    }

    protected function getTtlSeconds(): int
    {
        $ttl = (int) ($this->config['ttl'] ?? 1440);
        $unit = strtolower((string) ($this->config['ttl_unit'] ?? ''));

        // 显式指定单位时按指定单位解析
        if ($unit === 'seconds') {
            return max(1, $ttl);
        }
        if ($unit === 'minutes') {
            return max(1, $ttl * 60);
        }
        if ($unit === 'hours') {
            return max(1, $ttl * 3600);
        }

        // 未指定单位时的兼容策略：小值视为分钟，大值（>2880=48 小时）视为秒。
        // 该启发式仅为向后兼容保留，新代码建议显式配置 ttl_unit。
        if ($ttl <= 2880) {
            return max(1, $ttl * 60);
        }

        return max(1, $ttl);
    }

    protected function getRefreshTtlSeconds(): int
    {
        $refreshTtl = (int) ($this->config['refresh_ttl'] ?? 0);
        $unit = strtolower((string) ($this->config['refresh_ttl_unit'] ?? ''));

        // 显式指定单位时按指定单位解析
        if ($unit === 'seconds') {
            return max(0, $refreshTtl);
        }
        if ($unit === 'minutes') {
            return max(0, $refreshTtl * 60);
        }
        if ($unit === 'hours') {
            return max(0, $refreshTtl * 3600);
        }

        // 未指定单位时的兼容策略：小值视为分钟，大值（>43200=30 天）视为秒
        if ($refreshTtl <= 43200) {
            return max(0, $refreshTtl * 60);
        }

        return max(0, $refreshTtl);
    }

    protected function getBlacklistTtlSeconds(Payload $payload): int
    {
        $remaining = max(0, $payload->exp - time());
        $refresh = ($this->config['refresh_enabled'] ?? false) ? $this->getRefreshTtlSeconds() : 0;
        $ttl = $remaining + $refresh;

        return $ttl > 0 ? $ttl : 1;
    }

    /**
     * 生成高熵 JTI
     *
     * 使用随机字节而非时间戳前缀，降低可预测性，减少重放风险。
     *
     * @return string
     */
    protected static function generateJti(): string
    {
        return 'jwt_' . bin2hex(random_bytes(16));
    }

    /**
     * 存储Token信息
     */
    protected function storeToken(Payload $payload, string $token): void
    {
        // 如果启用了黑名单，则存储Token信息
        if ($this->config['blacklist_enabled'] ?? false) {
            // 存储Token与JTI的映射关系
            $key = "token:{$payload->jti}";
            $ttl = max(0, $payload->exp - time());

            if ($ttl > 0) {
                $this->storage->set($key, [
                    'jti' => $payload->jti,
                    'uid' => $payload->uid,
                    'username' => $payload->username,
                    'platform' => $payload->platform,
                    'iat' => $payload->iat,
                    'exp' => $payload->exp,
                    'token' => $token,
                    'roles' => $payload->roles,
                    'perms' => $payload->perms,
                    'custom' => $payload->custom
                ], $ttl);
            }
        }

        // 记录到用户活跃 Token 集合（SsoStorageInterface 优化路径）
        if ($this->storage instanceof SsoStorageInterface) {
            try {
                $uid = $this->normalizeUid($payload->uid);
                $platform = $this->normalizePlatform($payload->platform);
                $ttl = max(0, $payload->exp - time()) + $this->getRefreshTtlSeconds();
                $this->storage->trackUserToken($uid, $platform, $payload->jti, max(1, $ttl));
            } catch (JwtException $exception) {
                // uid / platform 缺失时不阻塞主流程，仅记录日志
                $this->logger->debug('跳过用户 Token 列表记录', [
                    'jti' => $payload->jti,
                    'reason' => $exception->getMessage(),
                ]);
            }
        }
    }

    /**
     * 获取Token信息
     *
     * @return array<string, mixed>|null
     */
    public function getTokenInfo(string $jti): ?array
    {
        $key = "token:{$jti}";
        return $this->storage->get($key);
    }

    /**
     * 获取用户的所有活跃Token
     *
     * 支持可选的平台过滤；不传时返回该用户所有平台。
     * 仅 SsoStorageInterface 实现了该能力，其他存储返回空数组。
     *
     * @param int|string $uid      用户 ID
     * @param string|null $platform 平台标识（可选）
     * @return array<string> JTI 列表
     */
    public function getUserActiveTokens(int|string $uid, ?string $platform = null): array
    {
        if (!$this->storage instanceof SsoStorageInterface) {
            return [];
        }

        $uid = (string) $uid;
        $key = $platform === null
            ? "user:{$uid}::tokens"
            : "user:{$uid}:{$platform}:tokens";

        $list = (array) $this->storage->get($key, []);
        return array_values(array_map('strval', $list));
    }

    /**
     * 检查是否唯一（由子类实现）
     */
    abstract public function isUnique(string $uid, string $platform): bool;

    /**
     * 注册Token（由子类实现）
     */
    abstract public function register(string $uid, string $platform, string $jti): void;

    /**
     * 防重放校验
     *
     * 当 Guard 注入了 AntiReplay 实例且处于启用模式时，
     * 在认证流程中根据 JTI + Nonce 组合进行一次性消费校验。
     * 命中重放时抛出 TokenReplayException。
     */
    protected function checkAntiReplay(Payload $payload, string $token): void
    {
        if ($this->antiReplay === null || !$this->antiReplay->isEnabled()) {
            return;
        }

        $ttl = max(1, $payload->exp - time());
        $passed = $this->antiReplay->check($payload->jti, $payload->getNonce(), $ttl);
        if (!$passed) {
            $this->logger->warning('检测到 Token 重放，已拒绝', [
                'jti' => $payload->jti,
                'platform' => $payload->platform,
                'uid' => $payload->uid,
            ]);
            throw new TokenReplayException(
                'Token replay detected',
                jti: $payload->jti,
                token: $token,
                nonce: $payload->getNonce()
            );
        }
    }
}
