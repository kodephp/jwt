<?php

namespace Kode\Jwt\Tests\Token;

use Kode\Jwt\Tests\TestCase;
use Kode\Jwt\Token\Payload;

class PayloadTest extends TestCase
{
    public function testPayloadCreation()
    {
        $payload = new Payload(
            uid: 123,
            username: 'john_doe',
            platform: 'app',
            exp: time() + 3600,
            iat: time(),
            jti: 'test_jti',
            roles: ['user', 'admin'],
            perms: ['read', 'write'],
            custom: ['department' => 'IT']
        );

        $this->assertEquals(123, $payload->uid);
        $this->assertEquals('john_doe', $payload->username);
        $this->assertEquals('app', $payload->platform);
        $this->assertEquals(['user', 'admin'], $payload->roles);
        $this->assertEquals(['read', 'write'], $payload->perms);
        $this->assertEquals(['department' => 'IT'], $payload->custom);
    }

    public function testPayloadToArray()
    {
        $payload = new Payload(
            uid: 123,
            username: 'john_doe',
            platform: 'app',
            exp: time() + 3600,
            iat: time(),
            jti: 'test_jti'
        );

        $array = $payload->toArray();
        
        $this->assertIsArray($array);
        $this->assertEquals(123, $array['uid']);
        $this->assertEquals('john_doe', $array['username']);
        $this->assertEquals('app', $array['platform']);
    }

    public function testPayloadFromArray()
    {
        $data = [
            'uid' => 123,
            'username' => 'john_doe',
            'platform' => 'app',
            'exp' => time() + 3600,
            'iat' => time(),
            'jti' => 'test_jti',
            'roles' => ['user', 'admin'],
            'perms' => ['read', 'write'],
            'custom' => ['department' => 'IT']
        ];

        $payload = Payload::fromArray($data);

        $this->assertEquals(123, $payload->uid);
        $this->assertEquals('john_doe', $payload->username);
        $this->assertEquals('app', $payload->platform);
        $this->assertEquals(['user', 'admin'], $payload->roles);
        $this->assertEquals(['read', 'write'], $payload->perms);
        $this->assertEquals(['department' => 'IT'], $payload->custom);
    }
    
    public function testPayloadCreateWithArrayCustomData()
    {
        $customData = ['department' => 'IT', 'level' => 5];
        $payload = Payload::create(
            uid: 123,
            username: 'john_doe',
            platform: 'app',
            exp: time() + 3600,
            iat: time(),
            jti: 'test_jti',
            roles: ['user', 'admin'],
            perms: ['read', 'write'],
            customData: $customData
        );

        $this->assertEquals(123, $payload->uid);
        $this->assertEquals('john_doe', $payload->username);
        $this->assertEquals('app', $payload->platform);
        $this->assertEquals(['user', 'admin'], $payload->roles);
        $this->assertEquals(['read', 'write'], $payload->perms);
        $this->assertEquals($customData, $payload->custom);
    }
    
    public function testPayloadCreateWithStringCustomData()
    {
        $encryptedData = 'encrypted_custom_data_string';
        $payload = Payload::create(
            uid: 123,
            username: 'john_doe',
            platform: 'app',
            exp: time() + 3600,
            iat: time(),
            jti: 'test_jti',
            roles: ['user', 'admin'],
            perms: ['read', 'write'],
            customData: $encryptedData
        );

        $this->assertEquals(123, $payload->uid);
        $this->assertEquals('john_doe', $payload->username);
        $this->assertEquals('app', $payload->platform);
        $this->assertEquals(['user', 'admin'], $payload->roles);
        $this->assertEquals(['read', 'write'], $payload->perms);
        $this->assertEquals(['encrypted_data' => $encryptedData], $payload->custom);
        $this->assertTrue($payload->hasEncryptedData());
        $this->assertEquals($encryptedData, $payload->getEncryptedData());
    }
    
    public function testPayloadCreateWithNullCustomData()
    {
        $payload = Payload::create(
            uid: 123,
            username: 'john_doe',
            platform: 'app',
            exp: time() + 3600,
            iat: time(),
            jti: 'test_jti',
            roles: ['user', 'admin'],
            perms: ['read', 'write'],
            customData: null
        );

        $this->assertEquals(123, $payload->uid);
        $this->assertEquals('john_doe', $payload->username);
        $this->assertEquals('app', $payload->platform);
        $this->assertEquals(['user', 'admin'], $payload->roles);
        $this->assertEquals(['read', 'write'], $payload->perms);
        $this->assertEquals([], $payload->custom);
    }
    
    public function testPayloadFromArrayWithMissingRequiredFields()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Missing required field: uid');

        $data = [
            'username' => 'john_doe',
            'platform' => 'app',
            'exp' => time() + 3600,
            'iat' => time(),
            'jti' => 'test_jti'
        ];

        Payload::fromArray($data);
    }
    
    public function testCustomDataMethods()
    {
        $payload = new Payload(
            uid: 123,
            username: 'john_doe',
            platform: 'app',
            exp: time() + 3600,
            iat: time(),
            jti: 'test_jti',
            custom: ['department' => 'IT', 'level' => 5]
        );

        $this->assertEquals('IT', $payload->getCustom('department'));
        $this->assertEquals(5, $payload->getCustom('level'));
        $this->assertEquals('default', $payload->getCustom('nonexistent', 'default'));
        $this->assertTrue($payload->hasCustom('department'));
        $this->assertFalse($payload->hasCustom('nonexistent'));
        $this->assertEquals(['department' => 'IT', 'level' => 5], $payload->getCustomData());
    }
    
    public function testRoleAndPermissionMethods()
    {
        $payload = new Payload(
            uid: 123,
            username: 'john_doe',
            platform: 'app',
            exp: time() + 3600,
            iat: time(),
            jti: 'test_jti',
            roles: ['user', 'admin'],
            perms: ['read', 'write']
        );

        $this->assertTrue($payload->hasRole('user'));
        $this->assertTrue($payload->hasRole('admin'));
        $this->assertFalse($payload->hasRole('nonexistent'));
        $this->assertTrue($payload->hasPermission('read'));
        $this->assertTrue($payload->hasPermission('write'));
        $this->assertFalse($payload->hasPermission('delete'));
    }
}