<?php

namespace Kode\Jwt\Exception;

class TokenInvalidException extends \Exception
{
    protected $message = 'Token is invalid';

    private ?string $reason = null;

    public function __construct(string $message = 'Token is invalid', string $reason = null)
    {
        parent::__construct($message);
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
