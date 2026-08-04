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

            $key = $signer['verifyKey'] ?? $signer['publicKey'] ?? $signer['key'] ?? '';

            // 非对称算法（RSA-PSS / ECDSA / EdDSA）签名带随机性，
            // 无法通过"重新签名后比对字节"来校验，必须走真正的验签流程。
            if (!Signer::verify($payload, $sig->signature, $sig->algorithm, (string) $key)) {
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
        // 与 sign()/getSignerKeyIds()/removeSigner() 保持一致：
        // 缺省 keyId 时按 "signer_{index}" 生成，确保 verify 能匹配到 sign 阶段生成的 keyId。
        foreach ($this->signers as $index => $signer) {
            $id = $signer['keyId'] ?? "signer_{$index}";
            if ($id === $keyId) {
                return $signer;
            }
        }
        return null;
    }

    /**
     * 统一委托 Signer 生成签名
     *
     * 修正点：
     *  - ECDSA 输出 RFC 7518 §3.4 规定的 R‖S 拼接（此前错误地直接输出 DER）
     *  - RSA-PSS 走真正的 EMSA-PSS 填充（此前错误地退化为 PKCS#1 v1.5）
     *  - EdDSA 通过 libsodium 支持
     *
     * @throws JwtException 当算法不支持或密钥非法时
     */
    private function computeSignature(string $data, string $key, Algorithm $algorithm): string
    {
        if ($key === '') {
            throw new JwtException("Signing key is required for multi-signature: {$algorithm->value}");
        }

        return Signer::sign($data, $algorithm, $key);
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
