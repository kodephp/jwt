<?php

namespace Kode\Jwt\Tests\Token;

use Kode\Jwt\Tests\TestCase;
use Kode\Jwt\Token\Builder;
use Kode\Jwt\Token\Parser;
use Kode\Jwt\Token\Payload;
use Kode\Jwt\Exception\TokenInvalidException;

class ParserTest extends TestCase
{
    public function testParseValidToken()
    {
        $config = [
            'algo' => 'HS256',
            'secret' => 'test_secret'
        ];
        
        $builder = new Builder($config);
        $parser = new Parser($config);
        
        $token = $builder
            ->setClaim('uid', 123)
            ->setClaim('username', 'John Doe')
            ->setClaim('platform', 'test')
            ->setClaim('iat', time())
            ->setClaim('exp', time() + 3600)
            ->setClaim('jti', 'test_jti')
            ->build();
        
        $payload = $parser->parse($token);
        
        $this->assertInstanceOf(Payload::class, $payload);
        $this->assertEquals(123, $payload->uid);
        $this->assertEquals('John Doe', $payload->username);
    }

    public function testParseInvalidTokenFormat()
    {
        $parser = new Parser([
            'algo' => 'HS256',
            'secret' => 'test_secret'
        ]);
        
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Invalid JSON in token part');
        
        $parser->parse('invalid.token.format');
    }

    public function testParseInvalidSignature()
    {
        $builder = new Builder([
            'algo' => 'HS256',
            'secret' => 'test_secret'
        ]);
        
        $parser = new Parser([
            'algo' => 'HS256',
            'secret' => 'different_secret'
        ]);
        
        $token = $builder
            ->setClaim('sub', '1234567890')
            ->setClaim('name', 'John Doe')
            ->setClaim('iat', time())
            ->setClaim('exp', time() + 3600)
            ->build();
        
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Invalid token signature');
        
        $parser->parse($token);
    }
}