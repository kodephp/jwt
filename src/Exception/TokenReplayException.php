<?php

declare(strict_types=1);

namespace Kode\Jwt\Exception;

/**
 * Token 重放攻击异常
 *
 * 当检测到 Token 在时间窗口内被重复使用（可能是重放攻击）时抛出。
 */
class TokenReplayException extends JwtException
{
    protected $message = 'Token replay detected';

    private ?string $nonce = null;
    private ?int $replayDetectedAt = null;

    public function __construct(
        string $message = 'Token replay detected',
        ?string $jti = null,
        ?string $token = null,
        ?string $nonce = null,
        int $code = 0,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous, $token, $jti);
        $this->nonce = $nonce;
        $this->replayDetectedAt = time();
    }

    /**
     * 获取触发重放的 Nonce
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * 获取重放检测时间
     */
    public function getReplayDetectedAt(): ?int
    {
        return $this->replayDetectedAt;
    }
}
