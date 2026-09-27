<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Config\ConfigLoader;
use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Event\EventDispatcher;
use Kode\Jwt\Exception\TokenBlacklistedException;
use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Guard\SsoGuard;
use Kode\Jwt\Storage\MemoryStorage;
use Kode\Jwt\Tests\Support\CountingStorage;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Parser;
use Kode\Jwt\Token\Payload;
use Kode\Jwt\Token\TokenManager;
use PHPUnit\Framework\TestCase;

/**
 * 「按 uid 撤销全部令牌」的**往返预算**。
 *
 * 为什么预算是契约而不是实现细节：这一枚方法是账号处置的唯一落地点
 * （禁用账号 / 禁用角色 / 删除角色 / 会话页那颗「清理过期会话」都调它），
 * 而调用方是在一个批次里逐账号问的。旧写法对**每一个**账号问一遍
 * `config('platforms')` 的七档平台清单（每档一次 `get()`），
 * 再把清单里每一枚 jti 各问一次详情（每枚一次 `get()`）——
 * 于是「一次点击」的代价 = 账号数 ×（7 + 令牌数）次串行往返。
 * 结果全对、一个错都不报，慢的那部分只体现在 worker 被按住多久上。
 *
 * 所以这一圈用例断言的是**调用序列**：清单一次批量读、详情一次批量读。
 * 只断言「撤销成功」的用例挡不住把 `getMultiple` 换回七次 `get`。
 */
final class RevokeBatchReadTest extends TestCase
{
    private const UID = '778812';

    /** @var array<string, string> 平台 => 刚签发的令牌（issueOn 填） */
    private array $issued = [];

    // ------------------------------------------------------------- 装配

    /**
     * 默认配置里的平台清单就是这个方法的全部成本来源，先钉住前提：
     * 少于七档时「批量」这条用例就没在测预算了。
     *
     * @return list<string>
     */
    private function platforms(ConfigLoader $config): array
    {
        $platforms = array_values(array_filter(
            (array) $config->get('platforms', []),
            static fn(mixed $p): bool => is_string($p) && $p !== ''
        ));

        self::assertGreaterThanOrEqual(
            7,
            count($platforms),
            '默认平台清单应至少七档（' . implode(',', $platforms) . '）—— 少了这条前提，本文件的往返断言是空的'
        );

        return $platforms;
    }

    /**
     * 真守卫、真签发、真黑名单：夹具走的是产品写路径，
     * 这样「清单键的写法」「详情键的形状」与线上同源，而不是我照着源码手搓的两份键名。
     *
     * 守卫刻意不配 `platform`：配了的话 `invalidate()` 会拒收别的平台的令牌
     * （Parser 的 platform 校验），七档平台就只有第一档撤得动。
     */
    private function guard(StorageInterface $storage): SsoGuard
    {
        $config = [
            'algo' => 'HS256',
            'secret' => 'revoke_batch_read_secret',
            'ttl' => 3600,
            'refresh_enabled' => true,
            'refresh_ttl' => 604800,
            'blacklist_enabled' => true,
        ];

        return new SsoGuard($storage, new Builder($config), new Parser($config), new EventDispatcher(), null, $config);
    }

    private function manager(CountingStorage $storage, SsoGuard $guard): TokenManager
    {
        return new TokenManager($storage, $guard, new ConfigLoader([]));
    }

    /**
     * 在指定平台签一枚真令牌，返回它的 jti。
     *
     * 每个账号每平台只签一枚：SSO 守卫签第二枚时会把第一枚拉黑，
     * 那是这一族的另一件事，别让它在往返用例里当噪声。
     */
    private function issueOn(SsoGuard $guard, StorageInterface $storage, string $platform): string
    {
        $now = time();
        $jti = $this->jtiOf($platform);
        $token = $guard->issue(new Payload(
            uid: self::UID,
            username: 'sweep_target',
            platform: $platform,
            exp: $now + 3600,
            iat: $now,
            jti: $jti
        ))['token'];

        self::assertIsString($token);
        $this->issued[$platform] = (string) $token;

        // 前提自查：产品写路径必须真的把 jti 记进了那一档平台的清单键。
        // 记不进的话下面的「批量撤销」会在一份空数据上测出「零次读取」的假绿。
        $list = (array) $storage->get($this->listKey($platform), []);
        self::assertContains($jti, $list, "签发后 {$platform} 的令牌清单里必须有这枚 jti（夹具与产品写路径同源）");

        return $jti;
    }

    /**
     * 在全部默认平台上各签一枚真令牌。
     *
     * @return array{0: CountingStorage, 1: TokenManager, 2: list<string>, 3: SsoGuard}
     */
    private function seeded(): array
    {
        $inner = new MemoryStorage(['limit' => 1000]);
        $storage = new CountingStorage($inner);
        $guard = $this->guard($storage);
        $platforms = $this->platforms(new ConfigLoader([]));

        foreach ($platforms as $platform) {
            $this->issueOn($guard, $storage, $platform);
        }
        self::assertCount(count($platforms), $this->issued, '前提：每档平台各签了一枚');

        $storage->resetReads();

        return [$storage, $this->manager($storage, $guard), $platforms, $guard];
    }

    protected function setUp(): void
    {
        $this->issued = [];
    }

    // ------------------------------------------------------------- 用例

    /**
     * 行为底线（这条在收口前后都必须绿）：跨平台签的令牌，一枚撤销调用之后全部失效，
     * 清单也清空。它挡住的是「为了批量把撤销做成半套」。
     */
    public function testRevokeInvalidatesTokensOnEveryPlatform(): void
    {
        [$storage, $manager, $platforms, $guard] = $this->seeded();

        $revoked = $manager->revokeUserTokens(self::UID);
        self::assertSame(count($platforms), $revoked, '每一档平台上那枚在发令牌都该被撤掉');

        foreach ($this->issued as $platform => $token) {
            $this->assertRevoked($guard, $token, $platform);
        }

        self::assertSame([], $manager->getUserTokens(self::UID), '撤销后活跃令牌清单应为空');
    }

    /**
     * 这一族的正题：七档平台的清单键必须**一次批量读**拿回，
     * 而不是逐档 `get()`。断言打在读序列上，因为两种写法的结果一模一样。
     */
    public function testRevokeReadsPlatformListsWithoutPerPlatformGet(): void
    {
        [$storage, $manager] = $this->seeded();

        $manager->revokeUserTokens(self::UID);

        $singles = array_values(array_filter(
            $storage->singleReadKeys(),
            static fn(string $key): bool => str_ends_with($key, ':tokens')
        ));
        self::assertSame(
            [],
            $singles,
            '逐平台清单读一枚就该红（' . implode(',', $singles) . '）：七档平台 = 七次串行往返，'
                . '而调用方是按账号循环的，这一圈乘出来就是「一次点击按住一枚 worker」'
        );
    }

    /**
     * 而且这些清单键必须**全部**出现在批量读里 —— 只批两档、其余靠默认值，
     * 上面那条用例照样绿（它只看「有没有单读」），实际后果是后面几档永久撤不掉。
     */
    public function testEveryPlatformListKeyIsCoveredByTheBatchRead(): void
    {
        [$storage, $manager, $platforms] = $this->seeded();

        $manager->revokeUserTokens(self::UID);

        $batched = $storage->keysOf('getMultiple');
        foreach ($platforms as $platform) {
            self::assertContains(
                $this->listKey($platform),
                $batched,
                "{$platform} 的清单没进批量读的那一份 —— 它要么被单读（另一条用例已点名），要么压根没被问"
            );
        }
    }

    /**
     * 令牌详情同理：清单里那些 `token:{jti}` 必须一次批量读，不许逐枚问。
     * 一枚账号可以有几十枚令牌（多平台 × 历史未清），这一档的往返数是会长的。
     */
    public function testTokenDetailsComeFromABatchRead(): void
    {
        [$storage, $manager, $platforms] = $this->seeded();

        $manager->revokeUserTokens(self::UID);

        $singles = array_values(array_filter(
            $storage->singleReadKeys(),
            static fn(string $key): bool => str_starts_with($key, 'token:')
        ));
        self::assertSame([], $singles, '逐枚读详情（' . implode(',', $singles) . '）= N 次往返');

        $batched = $storage->keysOf('getMultiple');
        foreach ($platforms as $platform) {
            self::assertContains(
                'token:' . $this->jtiOf($platform),
                $batched,
                "{$platform} 那枚令牌的详情没进批量读"
            );
        }
    }

    /**
     * 往返数本身也要有个上限：清单一次 + 详情一次 = 至多两次批量读。
     *
     * 下限同样要钉：只写「<= 2」的话，一次批量读都没发生的旧写法（七次 `get()`）
     * 拿 0 也满足，用例会在缺陷上绿 —— 而这一条的全部作用就是挡住那种退回。
     * 这份夹具每档平台都有一枚在发令牌，所以两批都必须发出去。
     */
    public function testRevokeCostsExactlyTwoBatchReadsPerAccount(): void
    {
        [$storage, $manager] = $this->seeded();

        $manager->revokeUserTokens(self::UID);

        $batches = $storage->countOf('getMultiple');
        self::assertGreaterThanOrEqual(
            2,
            $batches,
            '清单与详情各该有一次批量读；少于两次就是有哪一批压根没被问（上面那条覆盖用例挡的是漏档，这一条挡的是整批没读）'
        );
        self::assertLessThanOrEqual(
            2,
            $batches,
            '撤销一枚账号最多两次批量读（清单 + 详情）；第三次说明有循环退回逐枚问了'
        );
    }

    /**
     * 详情缺位时的退路不许被批量化弄丢：清单里有 jti、`token:{jti}` 却没读到，
     * 必须按 jti 入黑名单（撤了才算撤），而不是整枚跳过。
     */
    public function testMissingTokenDetailStillBlacklistsTheJti(): void
    {
        [$storage, $manager, $platforms, $guard] = $this->seeded();

        $jti = $this->jtiOf($platforms[0]);
        // 抹掉那一枚的详情：只留清单里那条 jti，模拟「详情已过期而清单还没滚存」
        self::assertTrue($storage->delete("token:{$jti}"));
        self::assertFalse($storage->has("token:{$jti}"));
        $storage->resetReads();

        $revoked = $manager->revokeUserTokens(self::UID);

        self::assertSame(count($platforms), $revoked, '详情读不到的那枚也要算进撤销数（按 jti 入黑名单）');
        self::assertTrue($storage->isBlacklisted($jti), '那枚必须真的进了黑名单');
    }

    /**
     * 指定平台那一支：只撤这一档，别的平台的令牌必须照旧能用。
     * 这一支同样不许逐枚单读。
     */
    public function testPlatformScopedRevokeLeavesOtherPlatformsAlone(): void
    {
        [$storage, $manager, $platforms, $guard] = $this->seeded();
        self::assertGreaterThanOrEqual(2, count($platforms));

        $target = $platforms[0];
        $other = $platforms[1];

        $revoked = $manager->revokeUserTokens(self::UID, $target);
        self::assertSame(1, $revoked);

        $this->assertRevoked($guard, $this->issued[$target], $target);

        $stillValid = $guard->authenticate($this->issued[$other]);
        self::assertSame($this->jtiOf($other), $stillValid->jti, "{$other} 的令牌必须还有效");

        self::assertSame(
            [],
            array_values(array_filter(
                $storage->singleReadKeys(),
                static fn(string $key): bool => str_ends_with($key, ':tokens') || str_starts_with($key, 'token:')
            )),
            '指定平台那一支也不许退回逐枚单读'
        );
    }

    /**
     * 指定平台时不许把别人的清单也读进来 —— 批量读是「一次问一批」，
     * 不是「一次问所有」。读全了再撤销，等于把作用域判错。
     */
    public function testPlatformScopedRevokeReadsOnlyThatPlatform(): void
    {
        [$storage, $manager, $platforms] = $this->seeded();
        $target = $platforms[0];
        $other = $platforms[1];

        $manager->revokeUserTokens(self::UID, $target);

        $batched = $storage->keysOf('getMultiple');
        self::assertContains($this->listKey($target), $batched);
        self::assertNotContains(
            $this->listKey($other),
            $batched,
            "指定平台撤销却把 {$other} 的清单一起读了"
        );
        self::assertSame(
            $this->jtiOf($other),
            $this->activeJtiOf($storage, $other),
            "{$other} 的清单必须原样还在"
        );
    }

    // ------------------------------------------------------------- 辅助

    private function listKey(string $platform): string
    {
        return 'user:' . self::UID . ":{$platform}:tokens";
    }

    private function jtiOf(string $platform): string
    {
        return 'jti_batch_' . substr(md5($platform), 0, 12);
    }

    private function activeJtiOf(StorageInterface $storage, string $platform): ?string
    {
        $list = (array) $storage->get($this->listKey($platform), []);

        return $list === [] ? null : (string) $list[0];
    }

    /**
     * 「撤过的令牌必须认证不过」只有一种问法：抛 TokenBlacklistedException。
     * 别的异常（签名/过期）说明它不是被这次撤销弄失效的，同样算失败。
     */
    private function assertRevoked(SsoGuard $guard, string $token, string $platform): void
    {
        try {
            $guard->authenticate($token);
        } catch (TokenBlacklistedException $e) {
            self::assertSame($this->jtiOf($platform), $e->getJti(), "{$platform}：被拉黑的应是这一枚");

            return;
        } catch (JwtException $e) {
            self::fail("{$platform}：撤销后的失败原因是 " . $e::class . '，不是黑名单');
        }

        self::fail("{$platform} 的令牌撤销后仍可通过认证");
    }
}
