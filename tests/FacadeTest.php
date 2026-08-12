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

    public function testBuilderReturnsIsolatedInstanceEachCall(): void
    {
        // builder() 必须每次返回全新实例，否则跨请求复用会累积 claims / 碰撞 jti
        KodeJwt::init(['guards' => ['api' => ['secret' => 's', 'algo' => 'HS256']]]);
        $a = KodeJwt::builder();
        $b = KodeJwt::builder();

        self::assertNotSame($a, $b, 'KodeJwt::builder() 不应返回共享单例');

        $a->setExpiration(time() + 3600)->setClaim('scope', 'read')->setClaim('iss', 'svc-a');
        $b->setExpiration(time() + 3600)->setClaim('scope', 'write');

        // 实例 a 的声明不应泄漏到实例 b
        $ta = $a->build();
        $tb = $b->build();

        $pa = json_decode(base64_decode(strtr(explode('.', $ta)[1], '-_', '+/')), true);
        $pb = json_decode(base64_decode(strtr(explode('.', $tb)[1], '-_', '+/')), true);

        self::assertSame('read', $pa['scope'] ?? null);
        self::assertSame('svc-a', $pa['iss'] ?? null);
        self::assertSame('write', $pb['scope'] ?? null);
        self::assertArrayNotHasKey('iss', $pb, '实例 a 的 claim 泄漏到了实例 b');
    }

    public function testBuilderResetClearsAccumulatedClaims(): void
    {
        KodeJwt::init(['guards' => ['api' => ['secret' => 's', 'algo' => 'HS256']]]);
        $builder = KodeJwt::builder();
        $builder->setExpiration(time() + 3600)->setClaim('role', 'admin')->setClaim('tid', 'x1');

        $first = json_decode(base64_decode(strtr(explode('.', $builder->build())[1], '-_', '+/')), true);
        self::assertSame('admin', $first['role'] ?? null);

        // 复用同一实例前 reset，避免上次 claims 残留 / jti 碰撞
        $builder->reset();
        $builder->setExpiration(time() + 3600)->setClaim('role', 'guest');

        $second = json_decode(base64_decode(strtr(explode('.', $builder->build())[1], '-_', '+/')), true);
        self::assertSame('guest', $second['role'] ?? null);
        self::assertArrayNotHasKey('tid', $second, 'reset() 未清除前次累积的 claim tid');
    }
}
