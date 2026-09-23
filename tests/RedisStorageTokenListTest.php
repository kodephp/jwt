<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Storage\MemoryStorage;
use Kode\Jwt\Storage\RedisStorage;
use PHPUnit\Framework\TestCase;
use Redis;

/**
 * `user:{uid}:{platform}:tokens` 的读写必须同型。
 *
 * trackUserToken() 用 LPUSH 把它写成原生 LIST（为了原子性和 50 条封顶），
 * 而读取方（TokenManager::revokeTokensFromList / collectPlatformTokens、
 * BaseGuard::getUserActiveTokens）走的是通用 `StorageInterface::get()`。
 * GET 一个 LIST 键是 WRONGTYPE，phpredis 不告警不抛错、直接返回 false，
 * 于是「按 uid 撤销该用户全部令牌」在 redis 驱动上恒查 0 条：
 * 强制下线点了没反应，接口还回 200。
 *
 * memory/file/database/apcu/memcached 五个实现都是 set/get 同一个值，
 * 天然同型；只有两个 redis 实现分叉。本用例把契约钉在「两个驱动读回来一样」。
 */
final class RedisStorageTokenListTest extends TestCase
{
    private ?Redis $raw = null;
    /** @var list<string> 测试期间写入的键（带前缀），tearDown 清理 */
    private array $rawKeys = [];

    private string $prefix = '';
    /** @var array<string, mixed> 被测 RedisStorage 的连接配置（与 setUp 里那条裸连接同源） */
    private array $config = [];

    protected function setUp(): void
    {
        if (!extension_loaded('redis')) {
            self::markTestSkipped('需要 redis 扩展');
        }

        $host = (string) (getenv('JWT_TEST_REDIS_HOST') ?: '127.0.0.1');
        $port = (int) (getenv('JWT_TEST_REDIS_PORT') ?: 6379);
        $password = (string) (getenv('JWT_TEST_REDIS_PASSWORD') ?: '');
        $database = (int) (getenv('JWT_TEST_REDIS_DB') ?: 0);

        $raw = @fsockopen($host, $port, $errno, $errstr, 1.0);
        if ($raw === false) {
            self::markTestSkipped("redis 不可达（{$host}:{$port}）：{$errstr}");
        }
        fclose($raw);

        $this->prefix = 'kode:jwt-test:' . bin2hex(random_bytes(4)) . ':';
        $this->config = [
            'host' => $host,
            'port' => $port,
            'password' => $password,
            'database' => $database,
        ];

        $redis = new Redis();
        $redis->connect($host, $port, 1.0);
        if ($password !== '') {
            $redis->auth($password);
        }
        $redis->select($database);
        $this->raw = $redis;
    }

    private function storage(): RedisStorage
    {
        return new RedisStorage($this->config + ['prefix' => $this->prefix]);
    }

    protected function tearDown(): void
    {
        if ($this->raw !== null && $this->rawKeys !== []) {
            $this->raw->del($this->rawKeys);
        }
        $this->raw?->close();
    }

    /**
     * 契约：trackUserToken 之后，同一个键必须能用 get() 把 jti 列表读回来，
     * 且新->旧排序、去重、50 条封顶。两个驱动逐条同判。
     */
    public function testTrackedListIsReadableOnBothDrivers(): void
    {
        foreach ($this->drivers() as $label => [$storage, $uid]) {
            $storage->trackUserToken($uid, 'web', 'jti_a', 3600);
            $storage->trackUserToken($uid, 'web', 'jti_b', 3600);
            $storage->trackUserToken($uid, 'web', 'jti_a', 3600);

            $list = (array) $storage->get("user:{$uid}:web:tokens", []);
            self::assertSame(
                ['jti_a', 'jti_b'],
                array_values($list),
                "{$label}：get() 必须读回 LPUSH 写进去的列表（最新在前，同一 JTI 只留一份）"
            );
        }
    }

    /** 列表封顶 50 条（无限增长的列表会把 redis 当成会话仓库撑爆）。 */
    public function testTrackedListIsCappedAt50(): void
    {
        foreach ($this->drivers() as $label => [$storage, $uid]) {
            for ($i = 0; $i < 60; $i++) {
                $storage->trackUserToken($uid, 'web', "jti_{$i}", 3600);
            }

            $list = (array) $storage->get("user:{$uid}:web:tokens", []);
            self::assertCount(50, $list, "{$label}：列表应封顶 50 条");
            self::assertSame('jti_59', $list[array_key_first($list)], "{$label}：最新一条应在首位");
        }
    }

    /**
     * 机制自证：旧读法为什么会失效。GET 打在 LIST 键上是 WRONGTYPE，
     * phpredis 静默返回 false（不告警、不抛异常），读取方据此认为「没有令牌」。
     * 若哪天 phpredis 改成抛异常，本用例会红，提示上面的修复前提变了。
     */
    public function testRawGetOnListKeyIsSilentlyFalse(): void
    {
        $key = $this->prefix . 'user:rawprobe:web:tokens';
        $this->rawKeys[] = $key;
        $this->raw->del($key);
        $this->raw->lPush($key, 'jti_x');

        self::assertFalse($this->raw->get($key), 'GET 打在 LIST 键上应返回 false（这正是失效的原因）');
        self::assertSame(Redis::REDIS_LIST, (int) $this->raw->type($key));
    }

    /** 撤销之后列表要能被清掉：revokeTokensFromList 走的是 delete(同一个键)。 */
    public function testTrackedListKeyIsDeletable(): void
    {
        $storage = $this->storage();
        $storage->trackUserToken('4242', 'web', 'jti_a', 3600);
        $key = $this->prefix . 'user:4242:web:tokens';
        $this->rawKeys[] = $key;

        self::assertTrue($storage->delete("user:4242:web:tokens"));
        self::assertSame([], (array) $storage->get('user:4242:web:tokens', []));
    }

    /**
     * 同型回退：如果这个键不是 LIST（历史数据、或别处用 set() 落成 JSON 串），
     * lRange 返回 false，读取必须退回普通 GET 而不是把值吞成空列表。
     */
    public function testNonListTokensKeyFallsBackToPlainGet(): void
    {
        $storage = $this->storage();
        $key = $this->prefix . 'user:4244:web:tokens';
        $this->rawKeys[] = $key;

        self::assertTrue($storage->set('user:4244:web:tokens', ['jti_legacy'], 3600));
        self::assertSame(Redis::REDIS_STRING, (int) $this->raw->type($key));
        self::assertSame(['jti_legacy'], (array) $storage->get('user:4244:web:tokens', []));
    }

    /** 列表键必须带 TTL：否则离线用户的历史令牌会永久占内存。 */
    public function testTrackedListCarriesTtl(): void
    {
        $storage = $this->storage();
        $storage->trackUserToken('4243', 'web', 'jti_a', 120);
        $key = $this->prefix . 'user:4243:web:tokens';
        $this->rawKeys[] = $key;

        $ttl = (int) $this->raw->ttl($key);
        self::assertGreaterThan(0, $ttl, 'TTL 应已设置（-1 表示键永不过期）');
        self::assertLessThanOrEqual(120, $ttl);
    }

    /**
     * @return array<string, array{0: \Kode\Jwt\Contract\StorageInterface, 1: string}>
     */
    private function drivers(): array
    {
        return [
            'memory' => [new MemoryStorage(), '1001'],
            'redis' => [$this->storage(), '1001'],
        ];
    }
}
