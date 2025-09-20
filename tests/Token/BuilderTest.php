<?php

namespace Kode\Jwt\Tests\Token;

use Kode\Jwt\Tests\TestCase;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Payload;

class BuilderTest extends TestCase
{
    public function testBuildTokenWithHs256()
    {
        $builder = new Builder([
            'algo' => 'HS256',
            'secret' => 'test_secret'
        ]);
        
        $payload = new Payload(
            uid: 123,
            username: 'john_doe',
            platform: 'app',
            exp: time() + 3600,
            iat: time(),
            jti: 'test_jti'
        );
        
        $token = $builder->fromPayload($payload)->build();
        
        $this->assertIsString($token);
        $this->assertStringContainsString('.', $token);
        
        $parts = explode('.', $token);
        $this->assertCount(3, $parts);
    }

    public function testBuildTokenWithCustomClaims()
    {
        $builder = new Builder([
            'algo' => 'HS256',
            'secret' => 'test_secret'
        ]);
        
        $token = $builder
            ->setClaim('sub', '1234567890')
            ->setClaim('name', 'John Doe')
            ->setClaim('iat', time())
            ->setClaim('exp', time() + 3600)
            ->build();
        
        $this->assertIsString($token);
        
        $parts = explode('.', $token);
        $this->assertCount(3, $parts);
    }
}