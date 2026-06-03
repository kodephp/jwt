<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Security\AntiReplay;
use Kode\Jwt\Contract\ReplayProtectionInterface;
use PHPUnit\Framework\TestCase;

/**
 * 防重放（Anti-Replay）保护器测试
 */
final class AntiReplayTest extends TestCase
{
    public function testDefaultModeIsOff(): void
    {
        $replay = new AntiReplay();
        self::assertSame(AntiReplay::MODE_OFF, $replay->getMode());
        self::assertFalse($replay->isEnabled());
    }

    public function testCheckPassesWhenDisabled(): void
    {
        $replay = new AntiReplay();
        self::assertTrue($replay->check('jti_test', 'nonce_abc', 3600));
    }

    public function testGenerateNonceHasExpectedLength(): void
    {
        $nonce = AntiReplay::generateNonce(16);
        self::assertSame(32, strlen($nonce)); // hex(16) = 32 chars
        self::assertMatchesRegularExpression('/^[a-f0-9]+$/', $nonce);
    }

    public function testGenerateNonceUniqueness(): void
    {
        $nonces = [];
        for ($i = 0; $i < 100; $i++) {
            $nonces[] = AntiReplay::generateNonce(8);
        }
        $unique = array_unique($nonces);
        self::assertCount(100, $unique, 'Nonce 生成应当保证唯一性');
    }

    public function testRequireNonceReturnsFalseWhenMissing(): void
    {
        $replay = new AntiReplay([
            'mode' => AntiReplay::MODE_STRICT,
            'require_nonce' => true,
        ]);
        self::assertTrue($replay->isRequireNonce());
        // 没有 backend 时，即使 require_nonce=true 也会通过
        self::assertTrue($replay->check('jti', null, 3600));
    }

    public function testStrictModeWithInMemoryBackend(): void
    {
        $replay = new AntiReplay([
            'mode' => AntiReplay::MODE_STRICT,
            'require_nonce' => true,
        ]);

        $fakeBackend = new class implements ReplayProtectionInterface {
            public array $store = [];

            public function checkAndStore(string $jti, string $nonce, int $ttl, int $window = 0): bool
            {
                $key = "{$jti}:{$nonce}";
                if (isset($this->store[$key])) {
                    return false;
                }
                $this->store[$key] = time() + $ttl;
                return true;
            }

            public function exists(string $jti, string $nonce): bool
            {
                return isset($this->store["{$jti}:{$nonce}"]);
            }

            public function purge(): int
            {
                $n = count($this->store);
                $this->store = [];
                return $n;
            }
        };

        $replay->withBackend($fakeBackend);

        // 第一次消费应通过
        self::assertTrue($replay->check('jti_a', 'nonce_1', 3600));
        // 第二次相同 nonce 应被拒绝
        self::assertFalse($replay->check('jti_a', 'nonce_1', 3600));
        // 不同 nonce 应通过
        self::assertTrue($replay->check('jti_a', 'nonce_2', 3600));
        // 不同 jti 应通过
        self::assertTrue($replay->check('jti_b', 'nonce_1', 3600));
    }

    public function testLenientModeSlidingWindow(): void
    {
        $replay = new AntiReplay([
            'mode' => AntiReplay::MODE_LENIENT,
            'window' => 60,
            'max_requests' => 3,
        ]);

        $fakeBackend = new class implements ReplayProtectionInterface {
            public function checkAndStore(string $jti, string $nonce, int $ttl, int $window = 0): bool
            {
                // 非严格模式下仅校验滑动窗口
                static $counter = [];
                $counter[$jti] = ($counter[$jti] ?? 0) + 1;
                return $counter[$jti] <= 3;
            }

            public function exists(string $jti, string $nonce): bool
            {
                return false;
            }

            public function purge(): int
            {
                return 0;
            }
        };

        $replay->withBackend($fakeBackend);

        self::assertTrue($replay->check('jti_x', 'n1', 3600));
        self::assertTrue($replay->check('jti_x', 'n2', 3600));
        self::assertTrue($replay->check('jti_x', 'n3', 3600));
        // 超过 max_requests 应被拒绝
        self::assertFalse($replay->check('jti_x', 'n4', 3600));
    }

    public function testSeenReturnsTrueWhenNonceExists(): void
    {
        $replay = new AntiReplay();
        $replay->withBackend(new class implements ReplayProtectionInterface {
            public function checkAndStore(string $jti, string $nonce, int $ttl, int $window = 0): bool
            {
                return true;
            }
            public function exists(string $jti, string $nonce): bool
            {
                return $jti === 'seen' && $nonce === 'nonce';
            }
            public function purge(): int
            {
                return 0;
            }
        });

        self::assertTrue($replay->seen('seen', 'nonce'));
        self::assertFalse($replay->seen('seen', 'unknown'));
    }
}
