<?php

declare(strict_types=1);

namespace Kode\Jwt\Exception;

class TokenInvalidException extends JwtException
{
    protected $message = 'Token is invalid';

    private ?string $reason = null;

    public function __construct(
        string $message = 'Token is invalid',
        ?string $reason = null,
        int $code = 0,
        ?\Throwable $previous = null,
        ?string $token = null,
        ?string $jti = null
    ) {
        parent::__construct($message, $code, $previous, $token, $jti);
        $this->reason = $reason;
    }

    /**
     * 获取无效原因
     */
    public function getReason(): ?string
    {
        return $this->reason;
    }

    /**
     * 设置无效原因
     */
    public function setReason(string $reason): self
    {
        $this->reason = $reason;
        return $this;
    }
}
