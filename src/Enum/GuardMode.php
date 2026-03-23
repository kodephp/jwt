<?php

declare(strict_types=1);

namespace Kode\Jwt\Enum;

enum GuardMode: string
{
    case SSO = 'sso';
    case MLO = 'mlo';

    public function isSso(): bool
    {
        return $this === self::SSO;
    }

    public function isMlo(): bool
    {
        return $this === self::MLO;
    }

    public function getDescription(): string
    {
        return match ($this) {
            self::SSO => 'Single Sign-On: One active token per user per platform',
            self::MLO => 'Multi-Login: Multiple active tokens per user per platform',
        };
    }

    public static function fromString(string $mode): self
    {
        return match (strtolower($mode)) {
            'sso', 'single', 'single_sign_on' => self::SSO,
            'mlo', 'multi', 'multi_login' => self::MLO,
            default => throw new \ValueError("Unknown guard mode: {$mode}"),
        };
    }
}
