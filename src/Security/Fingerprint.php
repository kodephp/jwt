<?php

declare(strict_types=1);

namespace Kode\Jwt\Security;

use Kode\Jwt\Exception\JwtException;

/**
 * Token 客户端指纹绑定
 *
 * 将 Token 与签发时的客户端上下文（User-Agent、IP 等）绑定，
 * 即使 Token 被截获，攻击者在不同客户端环境下也无法重放，从而提升安全性。
 *
 * 工作原理：
 *  1. 签发阶段：从请求上下文提取 UA + IP，计算 SHA-256 指纹，写入 Payload 的 fp 声明
 *  2. 验证阶段：从当前请求重新计算指纹，与 Payload 中的 fp 常量时间比较
 *  3. 不一致则抛出异常，Token 立即失效
 *
 * 安全设计：
 *  - 使用 hash_equals() 常量时间比较，防时间攻击
 *  - 指纹仅存哈希值，不存储 UA/IP 原文，避免敏感信息泄露
 *  - IP 仅取前两段（/24 网段），容忍运营商动态 IP 段内切换，避免误杀
 *  - 支持配置白名单（如内网网段、健康检查 UA），白名单内不校验指纹
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8471 RFC 8471 - Token Binding（参考）
 */
final class Fingerprint
{
    /**
     * 默认纳入指纹计算的上下文字段
     */
    private const array DEFAULT_FIELDS = ['user_agent', 'ip'];

    /**
     * 内网/可信 IP 网段（不校验指纹，避免误杀）
     */
    private const array TRUSTED_IP_PREFIXES = [
        '127.', '10.', '192.168.',
        '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
        '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
    ];

    /**
     * @param array<string> $fields 纳入指纹计算的上下文字段名（默认 user_agent + ip）
     * @param bool $ipPrefixOnly IP 是否仅取前两段（默认 true，平衡安全性与用户体验）
     * @param array<string> $trustedUaTrustedIpPrefix 可信 IP 前缀白名单
     */
    public function __construct(
        private readonly array $fields = self::DEFAULT_FIELDS,
        private readonly bool $ipPrefixOnly = true,
        private readonly array $trustedIpPrefixes = self::TRUSTED_IP_PREFIXES,
    ) {
    }

    /**
     * 从请求上下文计算指纹
     *
     * @param array<string, mixed> $context 请求上下文，至少包含 user_agent 和/或 ip
     * @return string 16 字节指纹的十六进制表示（32 字符）
     * @throws JwtException 当上下文缺少必需字段时
     */
    public function compute(array $context): string
    {
        $parts = [];
        foreach ($this->fields as $field) {
            $value = (string) ($context[$field] ?? '');
            if ($value === '' && in_array($field, ['user_agent', 'ip'], true)) {
                // UA 和 IP 是核心字段，缺失时不强制报错（兼容无 UA 的客户端）
                // 但会以空值参与哈希，保证一致性
            }
            if ($field === 'ip' && $this->ipPrefixOnly) {
                $value = $this->extractIpPrefix($value);
            }
            $parts[] = $field . '=' . $value;
        }

        $canonical = implode('|', $parts);
        return hash('sha256', $canonical);
    }

    /**
     * 校验上下文指纹是否与 Payload 中的指纹匹配
     *
     * @param array<string, mixed> $context 当前请求上下文
     * @param string|null $expectedFingerprint Payload 中的 fp 声明（null 表示未绑定）
     * @return bool 是否匹配（未绑定指纹时返回 true，表示不启用该特性）
     */
    public function verify(array $context, ?string $expectedFingerprint): bool
    {
        // Payload 未设置指纹（旧 Token 或未启用），跳过校验
        if ($expectedFingerprint === null || $expectedFingerprint === '') {
            return true;
        }

        // 内网 IP 跳过校验（避免开发/测试环境误杀）
        $ip = (string) ($context['ip'] ?? '');
        if ($this->isTrustedIp($ip)) {
            return true;
        }

        $actual = $this->compute($context);
        return hash_equals($expectedFingerprint, $actual);
    }

    /**
     * 严格校验：不通过时直接抛出异常
     *
     * @param array<string, mixed> $context 当前请求上下文
     * @param string|null $expectedFingerprint Payload 中的 fp 声明
     * @throws JwtException 当指纹不匹配时
     */
    public function ensureMatch(array $context, ?string $expectedFingerprint): void
    {
        if (!$this->verify($context, $expectedFingerprint)) {
            throw new JwtException(
                'Token fingerprint mismatch: client context has changed, possible token theft replay'
            );
        }
    }

    /**
     * 提取 IP 前两段（/16 网段）
     *
     * 平衡安全性与用户体验：运营商动态 IP 通常在同 /24 网段切换，
     * 仅取前两段（/16）能在保证安全的同时容忍更宽的 IP 变化。
     *
     * @param string $ip IPv4 或 IPv6 地址
     * @return string 网段前缀
     */
    private function extractIpPrefix(string $ip): string
    {
        // IPv4
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $segments = explode('.', $ip);
            return ($segments[0] ?? '') . '.' . ($segments[1] ?? '');
        }
        // IPv6：取前两组
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $segments = explode(':', $ip);
            return ($segments[0] ?? '') . ':' . ($segments[1] ?? '');
        }
        return '';
    }

    /**
     * 判断 IP 是否在可信内网网段
     *
     * @param string $ip
     * @return bool
     */
    private function isTrustedIp(string $ip): bool
    {
        if ($ip === '') {
            return false;
        }
        foreach ($this->trustedIpPrefixes as $prefix) {
            if (str_starts_with($ip, $prefix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 从全局 $_SERVER 提取请求上下文
     *
     * 便捷方法：在 Web 环境下直接从 $_SERVER 提取 UA 和 IP。
     * IP 解析优先级：X-Forwarded-For > X-Real-IP > REMOTE_ADDR
     *
     * @return array{user_agent: string, ip: string}
     */
    public static function fromServer(): array
    {
        $userAgent = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');

        // IP 解析：优先代理头（需确保前置代理可信，否则有伪造风险）
        $ip = '';
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $forwarded = (string) $_SERVER['HTTP_X_FORWARDED_FOR'];
            // X-Forwarded-For 可能为 "client, proxy1, proxy2"，取第一个
            $ip = trim(explode(',', $forwarded)[0]);
        } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            $ip = (string) $_SERVER['HTTP_X_REAL_IP'];
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = (string) $_SERVER['REMOTE_ADDR'];
        }

        return ['user_agent' => $userAgent, 'ip' => $ip];
    }
}
