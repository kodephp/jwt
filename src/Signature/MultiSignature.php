<?php

declare(strict_types=1);

namespace Kode\Jwt\Signature;

use Kode\Jwt\Enum\Algorithm;
use Kode\Jwt\Exception\JwtException;

final class MultiSignature
{
    /**
     * @param array<array{key: string, secret?: string, publicKey?: string,
     *     privateKey?: string, keyId?: string}> $signers
     */
    public function __construct(
        private array $signers,
        private ?string $detachedContent = null
    ) {
    }

    public function sign(string $payload, Algorithm $algorithm): array
    {
        $signatures = [];

        foreach ($this->signers as $index => $signer) {
            $key = $signer['key'] ?? '';
            $keyId = $signer['keyId'] ?? "signer_{$index}";

            $signature = $this->computeSignature($payload, $key, $algorithm);

            $signatures[] = new SignatureResult(
                signature: $signature,
                algorithm: $algorithm,
                keyId: $keyId
            );
        }

        return $signatures;
    }

    public function signDetached(string $content, Algorithm $algorithm): array
    {
        $this->detachedContent = $content;
        return $this->sign($content, $algorithm);
    }

    public function verify(string $payload, array $signatures): bool
    {
        if (empty($signatures)) {
            return false;
        }

        foreach ($signatures as $sig) {
            if (!$sig instanceof SignatureResult) {
                continue;
            }

            $signer = $this->findSigner($sig->keyId);
            if ($signer === null) {
                return false;
            }

            $key = $signer['key'] ?? '';
            $expected = $this->computeSignature($payload, $key, $sig->algorithm);

            if (!hash_equals($expected, $sig->signature)) {
                return false;
            }
        }

        return true;
    }

    public function verifyDetached(string $content, array $signatures): bool
    {
        return $this->verify($content, $signatures);
    }

    public function getSignerCount(): int
    {
        return count($this->signers);
    }

    public function getSignerKeyIds(): array
    {
        return array_map(
            fn($signer, $index) => $signer['keyId'] ?? "signer_{$index}",
            $this->signers,
            array_keys($this->signers)
        );
    }

    public function addSigner(array $signer): self
    {
        $newSigners = $this->signers;
        $newSigners[] = $signer;
        return new self($newSigners, $this->detachedContent);
    }

    public function removeSigner(string $keyId): self
    {
        $newSigners = array_filter(
            $this->signers,
            fn($signer, $index) => ($signer['keyId'] ?? "signer_{$index}") !== $keyId
        );
        return new self(array_values($newSigners), $this->detachedContent);
    }

    private function findSigner(string $keyId): ?array
    {
        foreach ($this->signers as $signer) {
            $id = $signer['keyId'] ?? '';
            if ($id === $keyId) {
                return $signer;
            }
        }
        return null;
    }

    private function computeSignature(string $data, string $key, Algorithm $algorithm): string
    {
        if ($algorithm->isHmac()) {
            return $this->signHmac($data, $key, $algorithm);
        }

        if ($algorithm->isRsa() || $algorithm->isRsapss()) {
            return $this->signAsymmetric($data, $key, $algorithm);
        }

        if ($algorithm->isEcdsa()) {
            return $this->signEcdsa($data, $key, $algorithm);
        }

        throw new JwtException("Unsupported algorithm for multi-signature: {$algorithm->value}");
    }

    private function signHmac(string $data, string $key, Algorithm $algorithm): string
    {
        $algo = match ($algorithm) {
            Algorithm::HS256 => 'sha256',
            Algorithm::HS384 => 'sha384',
            Algorithm::HS512 => 'sha512',
            default => throw new JwtException("Unsupported HMAC algorithm: {$algorithm->value}"),
        };

        return hash_hmac($algo, $data, $key, true);
    }

    private function signAsymmetric(string $data, string $key, Algorithm $algorithm): string
    {
        $opensslAlgo = match ($algorithm) {
            Algorithm::RS256 => OPENSSL_ALGO_SHA256,
            Algorithm::RS384 => OPENSSL_ALGO_SHA384,
            Algorithm::RS512 => OPENSSL_ALGO_SHA512,
            Algorithm::PS256 => OPENSSL_ALGO_SHA256,
            Algorithm::PS384 => OPENSSL_ALGO_SHA384,
            Algorithm::PS512 => OPENSSL_ALGO_SHA512,
            default => throw new JwtException("Unsupported RSA algorithm: {$algorithm->value}"),
        };

        $privateKey = openssl_pkey_get_private($key);
        if ($privateKey === false) {
            throw new JwtException('Invalid private key for RSA signature');
        }

        $signature = '';
        $success = openssl_sign($data, $signature, $privateKey, $opensslAlgo);

        if (!$success) {
            throw new JwtException('Failed to create RSA signature');
        }

        return $signature;
    }

    private function signEcdsa(string $data, string $key, Algorithm $algorithm): string
    {
        $opensslAlgo = match ($algorithm) {
            Algorithm::ES256 => OPENSSL_ALGO_SHA256,
            Algorithm::ES384 => OPENSSL_ALGO_SHA384,
            Algorithm::ES512 => OPENSSL_ALGO_SHA512,
            default => throw new JwtException("Unsupported ECDSA algorithm: {$algorithm->value}"),
        };

        $privateKey = openssl_pkey_get_private($key);
        if ($privateKey === false) {
            throw new JwtException('Invalid private key for ECDSA signature');
        }

        $signature = '';
        $success = openssl_sign($data, $signature, $privateKey, $opensslAlgo);

        if (!$success) {
            throw new JwtException('Failed to create ECDSA signature');
        }

        return $signature;
    }

    public static function fromArray(array $config): self
    {
        return new self(
            $config['signers'] ?? [],
            $config['detached_content'] ?? null
        );
    }

    public function toArray(): array
    {
        return [
            'signers' => $this->signers,
            'detached_content' => $this->detachedContent,
        ];
    }
}
