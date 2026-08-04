<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Claim\Confirmation;
use Kode\Jwt\Enum\Algorithm;
use Kode\Jwt\Key\JwkFactory;
use Kode\Jwt\Key\KeyConverter;
use Kode\Jwt\KodeJwt;
use Kode\Jwt\Security\DPoP\DPoPProofBuilder;
use Kode\Jwt\Security\DPoP\DPoPValidator;
use PHPUnit\Framework\TestCase;

/**
 * KodeJwt 门面新增能力测试（无需完整 init）
 */
final class FacadeTest extends TestCase
{
    public function testConfirmationFromJwk(): void
    {
        $pair = JwkFactory::generateEcKeyPair('P-256');
        $cnf = KodeJwt::confirmationFromJwk($pair['private']);

        self::assertInstanceOf(Confirmation::class, $cnf);
        self::assertSame($pair['public']->thumbprint('sha256'), $cnf->jkt);
    }

    public function testDpopBuilderAndValidator(): void
    {
        $pair = JwkFactory::generateEd25519KeyPair();
        $privatePem = KeyConverter::jwkToPrivatePem($pair['private']);

        $builder = KodeJwt::dpopBuilder(Algorithm::EdDSA, $privatePem);
        self::assertInstanceOf(DPoPProofBuilder::class, $builder);

        $validator = KodeJwt::dpopValidator();
        self::assertInstanceOf(DPoPValidator::class, $validator);

        $proof = $builder->build('GET', 'https://api.example.com/r');
        $result = $validator->validate($proof, 'GET', 'https://api.example.com/r');
        self::assertSame('GET', $result->htm);
    }

    public function testBuilderSetConfirmation(): void
    {
        $pair = JwkFactory::generateEcKeyPair('P-256');
        $cnf = KodeJwt::confirmationFromJwk($pair['private']);

        $builder = new \Kode\Jwt\Token\Builder([
            'secret' => 's', 'algo' => 'HS256', 'platform' => 'web',
        ]);
        $builder->setSubject('u')
            ->setExpiration(time() + 3600)
            ->setPlatform('web')
            ->setConfirmation($cnf);

        $token = $builder->build();
        // 解析后 cnf 声明应存在且 jkt 一致
        $parts = explode('.', $token);
        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
        self::assertArrayHasKey('cnf', $payload);
        self::assertSame($cnf->jkt, $payload['cnf']['jkt']);
    }
}
