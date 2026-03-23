<?php

declare(strict_types=1);

namespace Kode\Jwt\Signature;

use Kode\Jwt\Enum\Algorithm;

final readonly class SignatureResult
{
    public function __construct(
        public string $signature,
        public Algorithm $algorithm,
        public string $keyId = ''
    ) {
    }

    public function toString(): string
    {
        return base64_encode($this->signature);
    }

    public function withKeyId(string $keyId): self
    {
        return new self($this->signature, $this->algorithm, $keyId);
    }
}
