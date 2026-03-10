<?php

declare(strict_types=1);

namespace Kode\Jwt\Guard;

use Kode\Jwt\Contract\GuardInterface;
use Kode\Jwt\Contract\LoggerInterface;
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
use Kode\Jwt\Log\NullLogger;

abstract class BaseGuard implements GuardInterface
{
    protected StorageInterface $storage;
    protected Builder $builder;
    protected Parser $parser;
    protected EventDispatcher $eventDispatcher;
    protected LoggerInterface $logger;
    protected array $config;

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
     * 验证Token
     */
    public function authenticate(string $token): Payload
    {
        try {
            $payload = $this->parser->parse($token, $this->getExpectedPlatform());

            if ($this->storage->isBlacklisted($payload->jti)) {
                $this->logger->warning('Token 在黑名单中，认证失败', ['jti' => $payload->jti]);
                throw new TokenBlacklistedException(jti: $payload->jti, token: $token);
            }

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
        $oldPayload = $this->parser->parse($token, $this->getExpectedPlatform(), true);

        // 检查是否可以刷新
        if (!$this->canRefresh($token)) {
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
            $payload = $this->parser->parse($token, $this->getExpectedPlatform(), true);
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
     */
    protected function canRefresh(string $token): bool
    {
        // 检查是否启用刷新
        if (!($this->config['refresh_enabled'] ?? false)) {
            return false;
        }

        try {
            $payload = $this->parser->parse($token, $this->getExpectedPlatform(), true);

            // 检查是否在黑名单中
            if ($this->storage->isBlacklisted($payload->jti)) {
                return false;
            }

            // 计算刷新窗口期
            $refreshWindow = $payload->exp + $this->getRefreshTtlSeconds();

            // 检查是否在刷新窗口期内
            return time() <= $refreshWindow;
        } catch (TokenInvalidException $e) {
            return false;
        }
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
        $unit = (string) ($this->config['ttl_unit'] ?? '');

        if ($unit === 'seconds') {
            return max(1, $ttl);
        }

        if ($unit === 'minutes') {
            return max(1, $ttl * 60);
        }

        if ($ttl <= 2880) {
            return max(1, $ttl * 60);
        }

        return max(1, $ttl);
    }

    protected function getRefreshTtlSeconds(): int
    {
        $refreshTtl = (int) ($this->config['refresh_ttl'] ?? 0);
        $unit = (string) ($this->config['refresh_ttl_unit'] ?? '');

        if ($unit === 'seconds') {
            return max(0, $refreshTtl);
        }

        if ($unit === 'minutes') {
            return max(0, $refreshTtl * 60);
        }

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
    }

    /**
     * 获取Token信息
     */
    public function getTokenInfo(string $jti): ?array
    {
        $key = "token:{$jti}";
        return $this->storage->get($key);
    }

    /**
     * 获取用户的所有活跃Token
     */
    public function getUserActiveTokens(int $uid, ?string $platform = null): array
    {
        // 这个方法需要在具体的存储实现中处理
        // 这里提供一个通用的实现
        return [];
    }

    /**
     * 检查是否唯一（由子类实现）
     */
    abstract public function isUnique(string $uid, string $platform): bool;

    /**
     * 注册Token（由子类实现）
     */
    abstract public function register(string $uid, string $platform, string $jti): void;
}
