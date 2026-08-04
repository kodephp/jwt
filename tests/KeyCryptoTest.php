<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Enum\Algorithm;
use Kode\Jwt\Key\Jwk;
use Kode\Jwt\Key\JwkFactory;
use Kode\Jwt\Key\KeyConverter;
use Kode\Jwt\Signature\Signer;
use PHPUnit\Framework\TestCase;

/**
 * 密钥密码学能力测试
 *
 * 覆盖 RFC 7638 官方指纹向量、RFC 8037 OKP 指纹向量，
 * 以及 EC / Ed25519 的 JWK ↔ PEM 往返与签名验签。
 */
final class KeyCryptoTest extends TestCase
{
    /**
     * RFC 7638 §3.1 官方测试向量
     */
    public function testRfc7638RsaThumbprint(): void
    {
        $jwk = Jwk::fromArray([
            'kty' => 'RSA',
            'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
            'e' => 'AQAB',
            'alg' => 'RS256',
            'kid' => '2011-04-29',
        ]);

        self::assertSame('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', $jwk->thumbprint('sha256'));
    }

    /**
     * RFC 8037 A.3 OKP（Ed25519）指纹向量
     */
    public function testRfc8037OkpThumbprint(): void
    {
        $jwk = Jwk::fromArray([
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        ]);

        self::assertSame('kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k', $jwk->thumbprint('sha256'));
    }

    /**
     * EC P-256/384/521：JWK → PEM → 签名验签 + d 参数往返
     */
    public function testEcJwkToPemSignVerify(): void
    {
        foreach (['P-256' => Algorithm::ES256, 'P-384' => Algorithm::ES384, 'P-521' => Algorithm::ES512] as $curve => $alg) {
            $pair = JwkFactory::generateEcKeyPair($curve);
            $privatePem = KeyConverter::jwkToPrivatePem($pair['private']);
            $publicPem = KeyConverter::jwkToPem($pair['public']);

            $data = "ec-data-{$curve}";
            $signature = Signer::sign($data, $alg, $privatePem);
            self::assertTrue(Signer::verify($data, $signature, $alg, $publicPem), "{$curve} verify failed");

            // d 参数经 PEM → fromPem 往返一致
            $reimported = JwkFactory::fromPem($privatePem);
            self::assertSame($pair['private']->getParam('d'), $reimported->getParam('d'), "{$curve} d round-trip failed");
        }
    }

    /**
     * Ed25519：JWK → PEM → 签名验签
     */
    public function testEd25519JwkToPemSignVerify(): void
    {
        $pair = JwkFactory::generateEd25519KeyPair();
        $privatePem = KeyConverter::jwkToPrivatePem($pair['private']);
        $publicPem = KeyConverter::jwkToPem($pair['public']);

        $data = 'ed25519-data';
        $signature = Signer::sign($data, Algorithm::EdDSA, $privatePem);
        self::assertTrue(Signer::verify($data, $signature, Algorithm::EdDSA, $publicPem));
    }

    /**
     * fromPem 能识别 Ed25519 公钥
     */
    public function testFromPemIdentifiesEd25519(): void
    {
        $pair = JwkFactory::generateEd25519KeyPair();
        $publicPem = KeyConverter::jwkToPem($pair['public']);
        $jwk = JwkFactory::fromPem($publicPem);

        self::assertTrue($jwk->isOkp());
        self::assertSame('Ed25519', $jwk->getCurve());
        self::assertFalse($jwk->isPrivate());
    }
}
