<?php

namespace Kode\Jwt\Token;

class Claim
{
    // 注册声明
    public const ISSUER = 'iss';
    public const SUBJECT = 'sub';
    public const AUDIENCE = 'aud';
    public const EXPIRATION_TIME = 'exp';
    public const NOT_BEFORE = 'nbf';
    public const ISSUED_AT = 'iat';
    public const JWT_ID = 'jti';

    /**
     * 验证声明
     */
    public static function validate(string $name, mixed $value): bool
    {
        switch ($name) {
            case self::ISSUER:
            case self::SUBJECT:
            case self::AUDIENCE:
            case self::JWT_ID:
                return is_string($value) && !empty($value);

            case self::EXPIRATION_TIME:
            case self::NOT_BEFORE:
            case self::ISSUED_AT:
                return is_int($value) && $value > 0;

            default:
                // 自定义声明
                return true;
        }
    }

    /**
     * 获取声明名称的可读描述
     */
    public static function getDescription(string $name): string
    {
        $descriptions = [
            self::ISSUER => 'Issuer',
            self::SUBJECT => 'Subject',
            self::AUDIENCE => 'Audience',
            self::EXPIRATION_TIME => 'Expiration Time',
            self::NOT_BEFORE => 'Not Before',
            self::ISSUED_AT => 'Issued At',
            self::JWT_ID => 'JWT ID'
        ];

        return $descriptions[$name] ?? $name;
    }

    /**
     * 检查声明是否为时间类型
     */
    public static function isTimeClaim(string $name): bool
    {
        return in_array($name, [
            self::EXPIRATION_TIME,
            self::NOT_BEFORE,
            self::ISSUED_AT
        ]);
    }

    /**
     * 格式化时间声明值
     */
    public static function formatTime(int $timestamp): string
    {
        return date('Y-m-d H:i:s', $timestamp);
    }
}
