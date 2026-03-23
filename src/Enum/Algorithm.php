<?php

declare(strict_types=1);

namespace Kode\Jwt\Enum;

enum Algorithm: string
{
    case HS256 = 'HS256';
    case HS384 = 'HS384';
    case HS512 = 'HS512';
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';
    case PS256 = 'PS256';
    case PS384 = 'PS384';
    case PS512 = 'PS512';

    public function isHmac(): bool
    {
        return match ($this) {
            self::HS256, self::HS384, self::HS512 => true,
            default => false,
        };
    }

    public function isRsa(): bool
    {
        return match ($this) {
            self::RS256, self::RS384, self::RS512 => true,
            default => false,
        };
    }

    public function isEcdsa(): bool
    {
        return match ($this) {
            self::ES256, self::ES384, self::ES512 => true,
            default => false,
        };
    }

    public function isRsapss(): bool
    {
        return match ($this) {
            self::PS256, self::PS384, self::PS512 => true,
            default => false,
        };
    }

    public function isAsymmetric(): bool
    {
        return $this->isRsa() || $this->isEcdsa() || $this->isRsapss();
    }

    public function getKeyBits(): int
    {
        return match ($this) {
            self::HS256, self::RS256, self::ES256, self::PS256 => 256,
            self::HS384, self::RS384, self::ES384, self::PS384 => 384,
            self::HS512, self::RS512, self::ES512, self::PS512 => 512,
        };
    }

    public static function values(): array
    {
        return array_map(fn(self $case) => $case->value, self::cases());
    }

    public static function hmacAlgorithms(): array
    {
        return array_values(array_filter(
            self::cases(),
            fn(self $case) => $case->isHmac()
        ));
    }

    public static function asymmetricAlgorithms(): array
    {
        return array_values(array_filter(
            self::cases(),
            fn(self $case) => $case->isAsymmetric()
        ));
    }
}
