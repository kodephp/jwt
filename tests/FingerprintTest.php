<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Security\Fingerprint;
use PHPUnit\Framework\TestCase;

/**
 * Token 客户端指纹绑定单元测试
 */
class FingerprintTest extends TestCase
{
    /**
     * 相同上下文产生相同指纹
     */
    public function testSameContextProducesSameFingerprint(): void
    {
        $fp = new Fingerprint();
        $context = ['user_agent' => 'Mozilla/5.0', 'ip' => '203.0.113.5'];

        $hash1 = $fp->compute($context);
        $hash2 = $fp->compute($context);

        self::assertSame($hash1, $hash2);
        self::assertSame(64, strlen($hash1)); // SHA-256 十六进制 = 64 字符
    }

    /**
     * 不同 UA 产生不同指纹
     */
    public function testDifferentUaProducesDifferentFingerprint(): void
    {
        $fp = new Fingerprint();

        $hash1 = $fp->compute(['user_agent' => 'Mozilla/5.0', 'ip' => '203.0.113.5']);
        $hash2 = $fp->compute(['user_agent' => 'curl/8.0', 'ip' => '203.0.113.5']);

        self::assertNotSame($hash1, $hash2);
    }

    /**
     * 不同 IP 网段产生不同指纹
     */
    public function testDifferentIpSegmentProducesDifferentFingerprint(): void
    {
        $fp = new Fingerprint();

        $hash1 = $fp->compute(['user_agent' => 'UA', 'ip' => '203.0.113.5']);
        $hash2 = $fp->compute(['user_agent' => 'UA', 'ip' => '198.51.100.10']);

        self::assertNotSame($hash1, $hash2);
    }

    /**
     * IP 前两段相同（同 /16 网段）产生相同指纹
     */
    public function testSameIpPrefixProducesSameFingerprint(): void
    {
        $fp = new Fingerprint();

        // 203.0.113.5 与 203.0.200.10 在默认 ipPrefixOnly=true 下归一为 203.0
        $hash1 = $fp->compute(['user_agent' => 'UA', 'ip' => '203.0.113.5']);
        $hash2 = $fp->compute(['user_agent' => 'UA', 'ip' => '203.0.200.10']);

        self::assertSame($hash1, $hash2);
    }

    /**
     * verify：未绑定指纹时返回 true（向后兼容）
     */
    public function testVerifyReturnsTrueWhenFingerprintNotBound(): void
    {
        $fp = new Fingerprint();
        $context = ['user_agent' => 'UA', 'ip' => '203.0.113.5'];

        self::assertTrue($fp->verify($context, null));
        self::assertTrue($fp->verify($context, ''));
    }

    /**
     * verify：指纹匹配返回 true
     */
    public function testVerifyReturnsTrueOnMatch(): void
    {
        $fp = new Fingerprint();
        $context = ['user_agent' => 'Mozilla', 'ip' => '203.0.113.5'];

        $expected = $fp->compute($context);
        self::assertTrue($fp->verify($context, $expected));
    }

    /**
     * verify：指纹不匹配返回 false
     */
    public function testVerifyReturnsFalseOnMismatch(): void
    {
        $fp = new Fingerprint();

        $expected = $fp->compute(['user_agent' => 'UA', 'ip' => '203.0.113.5']);
        $current = ['user_agent' => 'attacker-browser', 'ip' => '198.51.100.1'];

        self::assertFalse($fp->verify($current, $expected));
    }

    /**
     * verify：内网 IP 跳过校验（避免误杀开发环境）
     */
    public function testVerifySkipsTrustedInternalIp(): void
    {
        $fp = new Fingerprint();
        $expected = $fp->compute(['user_agent' => 'UA', 'ip' => '203.0.113.5']);

        // 内网 IP 不校验
        $internalContext = ['user_agent' => 'different-ua', 'ip' => '127.0.0.1'];
        self::assertTrue($fp->verify($internalContext, $expected));

        $internalContext2 = ['user_agent' => 'different-ua', 'ip' => '192.168.1.1'];
        self::assertTrue($fp->verify($internalContext2, $expected));

        $internalContext3 = ['user_agent' => 'different-ua', 'ip' => '10.0.0.1'];
        self::assertTrue($fp->verify($internalContext3, $expected));
    }

    /**
     * ensureMatch：不匹配时抛出异常
     */
    public function testEnsureMatchThrowsOnMismatch(): void
    {
        $fp = new Fingerprint();
        $expected = $fp->compute(['user_agent' => 'UA', 'ip' => '203.0.113.5']);
        $current = ['user_agent' => 'attacker', 'ip' => '198.51.100.1'];

        $this->expectException(JwtException::class);
        $fp->ensureMatch($current, $expected);
    }

    /**
     * ensureMatch：匹配时不抛异常
     */
    public function testEnsureMatchPassesOnMatch(): void
    {
        $fp = new Fingerprint();
        $context = ['user_agent' => 'UA', 'ip' => '203.0.113.5'];
        $expected = $fp->compute($context);

        // 不应抛出异常
        $fp->ensureMatch($context, $expected);
        $this->addToAssertionCount(1);
    }

    /**
     * IPv6 也支持网段归一
     */
    public function testIpv6PrefixNormalization(): void
    {
        $fp = new Fingerprint();

        // 2001:db8::1 与 2001:db8::2 归一为 2001:db8
        $hash1 = $fp->compute(['user_agent' => 'UA', 'ip' => '2001:db8::1']);
        $hash2 = $fp->compute(['user_agent' => 'UA', 'ip' => '2001:db8::2']);

        self::assertSame($hash1, $hash2);
    }

    /**
     * 关闭 IP 前缀归一：完整 IP 参与哈希
     */
    public function testDisableIpPrefixOnlyUsesFullIp(): void
    {
        $fp = new Fingerprint(ipPrefixOnly: false);

        // 同 /16 网段但不同 IP，关闭归一后应不同
        $hash1 = $fp->compute(['user_agent' => 'UA', 'ip' => '203.0.113.5']);
        $hash2 = $fp->compute(['user_agent' => 'UA', 'ip' => '203.0.200.10']);

        self::assertNotSame($hash1, $hash2);
    }
}
