<?php

declare(strict_types=1);

namespace Kode\Jwt\OAuth2;

use Kode\Jwt\Contract\LoggerInterface;
use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Log\NullLogger;
use Kode\Jwt\Token\Parser;

/**
 * Token 撤销端点处理器（RFC 7009）
 *
 * 授权服务器通过撤销端点接收资源方/客户端的撤销请求，使 Token 立即失效。
 * 本实现将 Token 的 jti 加入黑名单（与 introspection / guard 共用存储），
 * 因此被撤销的 Token 在 introspection 与后续鉴权中都会被判定为失效。
 *
 * 安全设计（遵循 RFC 7009 §2.1）：
 *  - 无论 Token 是否存在/有效/已被撤销，撤销成功都返回 200 空体，
 *    避免通过响应差异枚举 Token 状态（侧通道防护）
 *  - 签名校验失败、解析失败一律视为「已撤销」，同样返回成功
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7009 RFC 7009 - OAuth 2.0 Token Revocation
 */
final class RevocationHandler
{
    private LoggerInterface $logger;

    public function __construct(
        private Parser $parser,
        private StorageInterface $storage,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * 撤销 Token
     *
     * @param string $token 待撤销的 Token（Access Token / Refresh Token）
     * @param string|null $tokenTypeHint 令牌类型提示（access_token / refresh_token），仅用于日志
     * @return RevocationResponse
     */
    public function revoke(string $token, ?string $tokenTypeHint = null): RevocationResponse
    {
        try {
            $payload = $this->parser->parse($token);
        } catch (\Throwable $e) {
            // 解析/验签失败：按 RFC 7009 视为已撤销（返回成功），不泄露原因
            $this->logger->debug('Token revocation: token unparseable, treated as already revoked', [
                'reason' => $e->getMessage(),
                'token_type_hint' => $tokenTypeHint,
            ]);
            return RevocationResponse::success();
        }

        if ($payload->jti === '') {
            $this->logger->debug('Token revocation: token has no jti, cannot blacklist');
            return RevocationResponse::success();
        }

        // 黑名单 TTL 取至 exp 的剩余时间（至少 60s，避免边界过早过期导致重放窗口）
        $ttl = max(60, $payload->exp - time());
        $this->storage->blacklist($payload->jti, $ttl);

        $this->logger->info('Token revoked', ['jti' => $payload->jti, 'ttl' => $ttl]);
        return RevocationResponse::success();
    }

    /**
     * 替换解析器实例（用于运行时切换算法或公钥）
     */
    public function setParser(Parser $parser): self
    {
        $this->parser = $parser;
        return $this;
    }

    /**
     * 替换存储实例（用于切换存储后端）
     */
    public function setStorage(StorageInterface $storage): self
    {
        $this->storage = $storage;
        return $this;
    }
}
