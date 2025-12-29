<?php

namespace Kode\Jwt\Exception;

class TokenExpiredException extends \Exception
{
    protected $message = 'Token has expired';

    private ?int $expiredAt = null;

    public function __construct(string $message = 'Token has expired', int $expiredAt = null)
    {
        parent::__construct($message);
        $this->expiredAt = $expiredAt;
    }

    /**
     * 获取Token过期时间
     */
    public function getExpiredAt(): ?int
    {
        return $this->expiredAt;
    }

    /**
     * 检查Token是否在刷新期内
     */
    public function isRefreshable(int $refreshTtl): bool
    {
        if ($this->expiredAt === null) {
            return false;
        }

        // 检查是否在刷新期内（过期时间 + 刷新期 > 当前时间）
        return (time() - $this->expiredAt) < ($refreshTtl * 60);
    }
}
