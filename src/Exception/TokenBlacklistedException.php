<?php

namespace Kode\Jwt\Exception;

class TokenBlacklistedException extends \Exception
{
    protected $message = 'Token has been blacklisted';
    
    private ?string $jti = null;
    private ?int $blacklistedAt = null;
    
    public function __construct(string $message = 'Token has been blacklisted', string $jti = null)
    {
        parent::__construct($message);
        $this->jti = $jti;
        $this->blacklistedAt = time();
    }
    
    /**
     * 获取Token的JTI
     */
    public function getJti(): ?string
    {
        return $this->jti;
    }
    
    /**
     * 获取被列入黑名单的时间
     */
    public function getBlacklistedAt(): ?int
    {
        return $this->blacklistedAt;
    }
    
    /**
     * 获取被列入黑名单的时长（秒）
     */
    public function getBlacklistedDuration(): int
    {
        if ($this->blacklistedAt === null) {
            return 0;
        }
        
        return time() - $this->blacklistedAt;
    }
}