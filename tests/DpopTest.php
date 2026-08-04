<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Enum\Algorithm;
use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Key\JwkFactory;
use Kode\Jwt\Key\KeyConverter;
use Kode\Jwt\Security\DPoP\DPoPProof;
use Kode\Jwt\Security\DPoP\DPoPProofBuilder;
use Kode\Jwt\Security\DPoP\DPoPValidator;
use PHPUnit\Framework\TestCase;

/**
 * DPoP 证明（RFC 9449）单元测试
 *
 * 覆盖 EC（P-256/384/521）与 Ed25519（OKP）的构建/校验往返，
 * 以及方法/URI/新鲜度/ath/nonce 的拒绝逻辑。
 */
final class DpopTest extends TestCase
{
    private function privatePem(string $curve): string
    {
        $pair = $curve === 'Ed25519'
            ? JwkFactory::generateEd25519KeyPair()
            : JwkFactory::generateEcKeyPair($curve);

        return KeyConverter::jwkToPrivatePem($pair['private']);
    }

    private function algorithmFor(string $curve): Algorithm
    {
        return match ($curve) {
            'P-256' => Algorithm::ES256,
            'P-384' => Algorithm::ES384,
            'P-521' => Algorithm::ES512,
            'Ed25519' => Algorithm::EdDSA,
        };
    }

    public function testEs256ProofRoundTrip(): void
    {
        $this->assertProofRoundTrip('P-256');
    }

    public function testEs384ProofRoundTrip(): void
    {
        $this->assertProofRoundTrip('P-384');
    }

    public function testEs512ProofRoundTrip(): void
    {
        $this->assertProofRoundTrip('P-521');
    }

    public function testEd25519ProofRoundTrip(): void
    {
        $this->assertProofRoundTrip('Ed25519');
    }

    private function assertProofRoundTrip(string $curve): void
    {
        $privatePem = $this->privatePem($curve);
        $alg = $this->algorithmFor($curve);

        $builder = new DPoPProofBuilder($alg, $privatePem, 'dpop-key-1');
        $proof = $builder->build('POST', 'https://resource.example.com/api/protected?x=1');

        $result = (new DPoPValidator())->validate($proof, 'POST', 'https://resource.example.com/api/protected?x=1');

        self::assertSame('POST', $result->htm);
        self::assertSame('https://resource.example.com/api/protected?x=1', $result->htu);
        self::assertNotNull($result->jkt);
        self::assertSame('dpop-key-1', $result->jwk->getKid());

        // jkt 必须匹配公钥 JWK 的 RFC 7638 指纹
        $publicJwk = JwkFactory::fromPem($privatePem)->toPublic();
        self::assertSame($publicJwk->thumbprint('sha256'), $result->jkt);
    }

    public function testWrongMethodRejected(): void
    {
        $privatePem = $this->privatePem('P-256');
        $proof = (new DPoPProofBuilder(Algorithm::ES256, $privatePem))
            ->build('GET', 'https://resource.example.com/path');

        $this->expectException(JwtException::class);
        (new DPoPValidator())->validate($proof, 'POST', 'https://resource.example.com/path');
    }

    public function testWrongUriRejected(): void
    {
        $privatePem = $this->privatePem('P-256');
        $proof = (new DPoPProofBuilder(Algorithm::ES256, $privatePem))
            ->build('GET', 'https://resource.example.com/path');

        $this->expectException(JwtException::class);
        (new DPoPValidator())->validate($proof, 'GET', 'https://resource.example.com/other');
    }

    public function testStaleProofRejected(): void
    {
        $privatePem = $this->privatePem('P-256');
        $proof = (new DPoPProofBuilder(Algorithm::ES256, $privatePem))
            ->build('GET', 'https://resource.example.com/path', null, null, time() - 600);

        $this->expectException(JwtException::class);
        (new DPoPValidator(maxAge: 300))->validate($proof, 'GET', 'https://resource.example.com/path');
    }

    public function testHmacRejectedByBuilder(): void
    {
        $this->expectException(JwtException::class);
        new DPoPProofBuilder(Algorithm::HS256, 'secret');
    }

    public function testAthBindingEnforced(): void
    {
        $privatePem = $this->privatePem('Ed25519');
        $accessToken = 'eyJhbGciOiJIUzI1NiJ9.abc.def';
        $ath = DPoPProof::accessTokenHash($accessToken);

        $proof = (new DPoPProofBuilder(Algorithm::EdDSA, $privatePem))
            ->build('GET', 'https://resource.example.com/path', $accessToken);

        // 未要求 ath 时应通过，且 ath 正确
        $ok = (new DPoPValidator())->validate($proof, 'GET', 'https://resource.example.com/path');
        self::assertSame($ath, $ok->ath);

        // 要求错误 ath 应拒绝
        $this->expectException(JwtException::class);
        (new DPoPValidator(expectedAth: 'wrong-ath'))->validate($proof, 'GET', 'https://resource.example.com/path');
    }

    public function testNonceBindingEnforced(): void
    {
        $privatePem = $this->privatePem('P-256');
        $proof = (new DPoPProofBuilder(Algorithm::ES256, $privatePem))
            ->build('GET', 'https://resource.example.com/path', null, 'server-nonce-123');

        // 未要求 nonce，应通过
        $ok = (new DPoPValidator())->validate($proof, 'GET', 'https://resource.example.com/path');
        self::assertSame('server-nonce-123', $ok->nonce);

        // 要求不同 nonce，应拒绝
        $this->expectException(JwtException::class);
        (new DPoPValidator(expectedNonce: 'other-nonce'))->validate($proof, 'GET', 'https://resource.example.com/path');
    }
}
