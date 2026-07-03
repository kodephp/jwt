<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Exception\JwtException;
use Kode\Jwt\Key\Jwk;
use Kode\Jwt\Key\JwkFactory;
use Kode\Jwt\Key\JwkSet;
use Kode\Jwt\Key\KeyConverter;
use PHPUnit\Framework\TestCase;

/**
 * JWK (JSON Web Key) 模块单元测试
 *
 * 覆盖 Jwk 值对象、JwkSet 集合、KeyConverter 互转、JwkFactory 生成。
 */
class JwkTest extends TestCase
{
    /**
     * Jwk 基础创建与序列化
     */
    public function testCreateOctJwkAndSerialize(): void
    {
        $jwk = Jwk::create('oct', ['k' => 'Zm9vYmFy'], 'sig', null, 'HS256', 'kid-1');

        self::assertSame('oct', $jwk->getKty());
        self::assertSame('HS256', $jwk->getAlg());
        self::assertSame('kid-1', $jwk->getKid());
        self::assertTrue($jwk->isSymmetric());
        self::assertFalse($jwk->isAsymmetric());
        self::assertTrue($jwk->isPrivate());

        $arr = $jwk->toArray();
        self::assertSame('oct', $arr['kty']);
        self::assertSame('Zm9vYmFy', $arr['k']);
        self::assertSame('HS256', $arr['alg']);
        self::assertSame('kid-1', $arr['kid']);
        self::assertSame('sig', $arr['use']);
    }

    /**
     * kty 大小写不敏感归一化
     */
    public function testKtyNormalizationIsCaseInsensitive(): void
    {
        $jwk = Jwk::create('rsa');
        self::assertSame('RSA', $jwk->getKty());

        $jwk2 = Jwk::create('OCT');
        self::assertSame('oct', $jwk2->getKty());
    }

    /**
     * 不支持的 kty 抛出异常
     */
    public function testUnsupportedKtyThrows(): void
    {
        $this->expectException(JwtException::class);
        Jwk::create('DES');
    }

    /**
     * toPublic 剥离私钥参数
     */
    public function testToPublicStripsPrivateParams(): void
    {
        $jwk = Jwk::create('RSA', [
            'n' => 'public-modulus',
            'e' => 'AQAB',
            'd' => 'private-exponent',
            'p' => 'prime1',
            'q' => 'prime2',
        ], kid: 'k1');

        self::assertTrue($jwk->isPrivate());

        $public = $jwk->toPublic();
        self::assertFalse($public->isPrivate());
        self::assertSame('public-modulus', $public->getParam('n'));
        self::assertSame('AQAB', $public->getParam('e'));
        self::assertNull($public->getParam('d'));
        self::assertNull($public->getParam('p'));
        self::assertNull($public->getParam('q'));
    }

    /**
     * fromArray / fromJson 反序列化
     */
    public function testFromArrayAndFromJsonRoundTrip(): void
    {
        $data = [
            'kty' => 'oct',
            'k' => 'c2VjcmV0LWtleQ',
            'alg' => 'HS256',
            'kid' => 'round-trip',
            'use' => 'sig',
        ];

        $jwk = Jwk::fromArray($data);
        self::assertSame('oct', $jwk->getKty());
        self::assertSame('HS256', $jwk->getAlg());
        self::assertSame('round-trip', $jwk->getKid());

        $json = $jwk->toJson();
        $reborn = Jwk::fromJson($json);
        self::assertSame($jwk->toArray(), $reborn->toArray());
    }

    /**
     * 非法 JSON 抛出异常
     */
    public function testFromJsonRejectsInvalidJson(): void
    {
        $this->expectException(JwtException::class);
        Jwk::fromJson('{invalid json');
    }

    /**
     * computeKid 基于公钥参数生成确定性 kid
     */
    public function testComputeKidIsDeterministic(): void
    {
        $jwk1 = Jwk::create('RSA', ['n' => 'n-value', 'e' => 'AQAB']);
        $jwk2 = Jwk::create('RSA', ['n' => 'n-value', 'e' => 'AQAB']);
        $jwk3 = Jwk::create('RSA', ['n' => 'different', 'e' => 'AQAB']);

        self::assertSame($jwk1->computeKid(), $jwk2->computeKid());
        self::assertNotSame($jwk1->computeKid(), $jwk3->computeKid());
    }

    /**
     * __toString 不泄露密钥内容
     */
    public function testToStringDoesNotLeakSecrets(): void
    {
        $jwk = Jwk::create('oct', ['k' => 'super-secret-key'], alg: 'HS256', kid: 'k1');
        $str = (string) $jwk;

        self::assertStringNotContainsString('super-secret-key', $str);
        self::assertStringContainsString('oct', $str);
        self::assertStringContainsString('k1', $str);
        self::assertStringContainsString('private=yes', $str);
    }

    /**
     * JwkSet 集合操作
     */
    public function testJwkSetOperations(): void
    {
        $jwk1 = Jwk::create('oct', ['k' => 'k1'], kid: 'kid-1');
        $jwk2 = Jwk::create('oct', ['k' => 'k2'], kid: 'kid-2');
        $set = JwkSet::fromArray([$jwk1, $jwk2]);

        self::assertSame(2, $set->count());
        self::assertTrue($set->has('kid-1'));
        self::assertSame($jwk1, $set->get('kid-1'));

        // 不可变添加
        $jwk3 = Jwk::create('oct', ['k' => 'k3'], kid: 'kid-3');
        $newSet = $set->with($jwk3);
        self::assertSame(2, $set->count());
        self::assertSame(3, $newSet->count());

        // 不可变移除
        $removedSet = $newSet->without('kid-2');
        self::assertTrue($newSet->has('kid-2'));
        self::assertFalse($removedSet->has('kid-2'));
    }

    /**
     * JwkSet 不存在的 kid 抛出异常
     */
    public function testJwkSetGetThrowsOnMissingKid(): void
    {
        $set = new JwkSet([]);
        $this->expectException(JwtException::class);
        $set->get('non-existent');
    }

    /**
     * JwkSet JSON 序列化与反序列化
     */
    public function testJwkSetJsonRoundTrip(): void
    {
        $jwk = Jwk::create('oct', ['k' => 'val'], alg: 'HS256', kid: 'k1');
        $set = new JwkSet(['k1' => $jwk]);

        $json = $set->toJson();
        $reborn = JwkSet::fromJson($json);

        self::assertSame(1, $reborn->count());
        self::assertSame('k1', $reborn->get('k1')->getKid());
    }

    /**
     * JwkSet toPublic 剥离所有私钥
     */
    public function testJwkSetToPublic(): void
    {
        $private = Jwk::create('RSA', ['n' => 'n', 'e' => 'e', 'd' => 'd'], kid: 'k1');
        $set = new JwkSet(['k1' => $private]);
        $publicSet = $set->toPublic();

        self::assertTrue($set->get('k1')->isPrivate());
        self::assertFalse($publicSet->get('k1')->isPrivate());
    }

    /**
     * JwkFactory 生成对称密钥
     */
    public function testFactoryGeneratesOctKeyWithCorrectLength(): void
    {
        $jwk256 = JwkFactory::generateOctKey('HS256', 'kid-a');
        self::assertSame('oct', $jwk256->getKty());
        self::assertSame('HS256', $jwk256->getAlg());
        self::assertSame('kid-a', $jwk256->getKid());

        // HS256 = 32 字节 = base64url 编码后约 43 字符（无填充）
        $k = $jwk256->getParam('k');
        self::assertNotNull($k);
        $decoded = base64_decode(strtr($k, '-_', '+/'));
        self::assertSame(32, strlen($decoded));

        // HS512 = 64 字节
        $jwk512 = JwkFactory::generateOctKey('HS512');
        $k512 = $jwk512->getParam('k');
        $decoded512 = base64_decode(strtr($k512 ?? '', '-_', '+/'));
        self::assertSame(64, strlen($decoded512));
    }

    /**
     * JwkFactory 不支持的对称算法抛出异常
     */
    public function testFactoryRejectsUnsupportedAlg(): void
    {
        $this->expectException(JwtException::class);
        JwkFactory::generateOctKey('HS128');
    }

    /**
     * JwkFactory 生成 RSA 密钥对，并验证公私钥关系
     */
    public function testFactoryGeneratesRsaKeyPair(): void
    {
        $pair = JwkFactory::generateRsaKeyPair(2048, 'RS256', 'kid-rsa');

        self::assertSame('RSA', $pair['private']->getKty());
        self::assertSame('RSA', $pair['public']->getKty());
        self::assertTrue($pair['private']->isPrivate());
        self::assertFalse($pair['public']->isPrivate());

        // 公钥参数 n 应相同
        self::assertSame($pair['private']->getParam('n'), $pair['public']->getParam('n'));
        self::assertSame($pair['private']->getParam('e'), $pair['public']->getParam('e'));

        // kid 应一致
        self::assertSame('kid-rsa', $pair['private']->getKid());
        self::assertSame('kid-rsa', $pair['public']->getKid());
    }

    /**
     * RSA 密钥位数低于 2048 抛出异常
     */
    public function testFactoryRejectsInsecureRsaSize(): void
    {
        $this->expectException(JwtException::class);
        JwkFactory::generateRsaKeyPair(1024);
    }

    /**
     * KeyConverter: RSA 私钥 PEM → JWK → 公钥 JWK → PEM 往返
     */
    public function testKeyConverterRsaRoundTrip(): void
    {
        // 生成测试密钥对
        $keyResource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $privatePem = '';
        openssl_pkey_export($keyResource, $privatePem);

        // 私钥 → JWK
        $privateJwk = KeyConverter::rsaPrivateKeyToJwk($privatePem, 'kid-pem', 'RS256');
        self::assertSame('RSA', $privateJwk->getKty());
        self::assertTrue($privateJwk->isPrivate());

        // 公钥 JWK → PEM
        $publicJwk = $privateJwk->toPublic();
        $regeneratedPem = KeyConverter::jwkToPem($publicJwk);

        // 重新生成的 PEM 应能被 OpenSSL 解析
        $key = openssl_pkey_get_public($regeneratedPem);
        self::assertNotFalse($key);

        // 验证签名/验签往返一致
        $data = 'test-data';
        openssl_sign($data, $signature, $privatePem, OPENSSL_ALGO_SHA256);
        $verify = openssl_verify($data, $signature, $regeneratedPem, OPENSSL_ALGO_SHA256);
        self::assertSame(1, $verify);
    }

    /**
     * KeyConverter: oct ↔ JWK 往返
     */
    public function testKeyConverterOctRoundTrip(): void
    {
        $secret = 'my-super-secret-key';
        $jwk = KeyConverter::octToJwk($secret, 'kid-oct', 'HS256');
        self::assertSame('oct', $jwk->getKty());

        $recovered = KeyConverter::jwkToOct($jwk);
        self::assertSame($secret, $recovered);
    }

    /**
     * KeyConverter: 非 RSA JWK 转 PEM 抛出异常
     */
    public function testKeyConverterRejectsNonRsaForPem(): void
    {
        $jwk = Jwk::create('oct', ['k' => 'val']);
        $this->expectException(JwtException::class);
        KeyConverter::jwkToPem($jwk);
    }

    /**
     * JwkFactory::fromSecret 便捷方法
     */
    public function testFromSecretCreatesJwk(): void
    {
        $jwk = JwkFactory::fromSecret('raw-secret', 'HS256', 'kid-x');
        self::assertSame('oct', $jwk->getKty());
        self::assertSame('HS256', $jwk->getAlg());
        self::assertSame('kid-x', $jwk->getKid());
    }
}
