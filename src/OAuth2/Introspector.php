<?php

declare(strict_types=1);

namespace Kode\Jwt\OAuth2;

use Kode\Jwt\Contract\LoggerInterface;
use Kode\Jwt\Contract\StorageInterface;
use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Exception\TokenBlacklistedException;
use Kode\Jwt\Exception\TokenExpiredException;
use Kode\Jwt\Exception\TokenInvalidException;
use Kode\Jwt\Log\NullLogger;
use Kode\Jwt\Token\Parser;
use Kode\Jwt\Token\Payload;

/**
 * Token Introspection 服务（RFC 7662 §2.1）
 *
 * OAuth2 授权服务器通过 introspection 端点接收资源服务器的查询请求，
 * 校验 Token 当前是否有效，并返回对应的 {@see IntrospectionResponse}。
 *
 * 工作流程：
 *  1. 解析并验签 Token（含平台/声明校验）
 *  2. 检查黑名单（若启用），命中则返回 active=false
 *  3. 返回 active=true 的响应，附带 Payload 中的标准声明
 *
 * 安全设计：
 *  - 任何异常（格式错误、签名错误、过期、黑名单）统一返回 active=false
 *    不向调用方泄露失败原因，避免信息侧通道
 *  - 不解析 Refresh Token，仅处理 Access Token / ID Token
 *  - 业务侧应在调用 introspect 前自行认证资源服务器身份
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7662 RFC 7662 - Token Introspection
 */
final class Introspector
{
    private LoggerInterface $logger;

    /**
     * 构造函数
     *
     * @param Parser $parser 已配置公钥/密钥的解析器
     * @param StorageInterface $storage 存储实例，用于黑名单检查
     * @param LoggerInterface|null $logger 日志实例，未提供时使用 NullLogger
     */
    public function __construct(
        private Parser $parser,
        private StorageInterface $storage,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * 内省 Token 当前状态
     *
     * @param string $token 待查询的 Token
     * @param string|null $expectedPlatform 期望的平台标识，传入后强制匹配
     * @param string|null $clientId 资源方客户端 ID（写入响应）
     * @return IntrospectionResponse
     */
    public function introspect(
        string $token,
        ?string $expectedPlatform = null,
        ?string $clientId = null,
    ): IntrospectionResponse {
        // 步骤 1：解析并验签
        try {
            $payload = $this->parser->parse($token, $expectedPlatform);
        } catch (TokenExpiredException | TokenInvalidException | TokenBlacklistedException | JwtException $e) {
            $this->logger->debug('Token introspection 失败：解析或签名校验未通过', [
                'reason' => $e->getMessage(),
            ]);
            return IntrospectionResponse::inactive();
        }

        // 步骤 2：黑名单检查
        if ($payload->jti !== '' && $this->storage->isBlacklisted($payload->jti)) {
            $this->logger->debug('Token introspection 失败：JTI 命中黑名单', [
                'jti' => $payload->jti,
            ]);
            return IntrospectionResponse::inactive();
        }

        // 步骤 3：构造 active=true 响应
        return IntrospectionResponse::fromPayload($payload, $clientId);
    }

    /**
     * 仅基于 Payload 构造响应（用于业务侧已自行完成解析的场景）
     *
     * @param Payload $payload 已校验的 Payload
     * @param string|null $clientId 客户端 ID
     * @return IntrospectionResponse
     */
    public function fromPayload(Payload $payload, ?string $clientId = null): IntrospectionResponse
    {
        if ($payload->jti !== '' && $this->storage->isBlacklisted($payload->jti)) {
            return IntrospectionResponse::inactive();
        }
        return IntrospectionResponse::fromPayload($payload, $clientId);
    }

    /**
     * 替换解析器实例（用于运行时切换算法或公钥）
     *
     * @param Parser $parser
     * @return self
     */
    public function setParser(Parser $parser): self
    {
        $this->parser = $parser;
        return $this;
    }

    /**
     * 替换存储实例（用于切换存储后端）
     *
     * @param StorageInterface $storage
     * @return self
     */
    public function setStorage(StorageInterface $storage): self
    {
        $this->storage = $storage;
        return $this;
    }

    /**
     * 替换日志实例
     *
     * @param LoggerInterface $logger
     * @return self
     */
    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;
        return $this;
    }
}
