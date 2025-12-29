<?php

namespace Kode\Jwt\Exception;

class JwtException extends \Exception
{
    protected ?string $token = null;
    protected ?string $jti = null;

    public function __construct(
        string $message = "",
        int $code = 0,
        ?\Throwable $previous = null,
        ?string $token = null,
        ?string $jti = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->token = $token;
        $this->jti = $jti;
    }

    /**
     * 获取Token
     */
    public function getToken(): ?string
    {
        return $this->token;
    }

    /**
     * 获取JTI
     */
    public function getJti(): ?string
    {
        return $this->jti;
    }

    /**
     * 设置Token
     */
    public function setToken(string $token): self
    {
        $this->token = $token;
        return $this;
    }

    /**
     * 设置JTI
     */
    public function setJti(string $jti): self
    {
        $this->jti = $jti;
        return $this;
    }
}
