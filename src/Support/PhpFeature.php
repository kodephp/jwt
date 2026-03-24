<?php

declare(strict_types=1);

namespace Kode\Jwt\Support;

/**
 * PHP 版本特性检测工具
 *
 * 根据运行时 PHP 版本提供不同实现
 */
final class PhpFeature
{
    /**
     * 检测是否支持管道操作符 (PHP 8.5+)
     */
    public static function supportsPipeOperator(): bool
    {
        return version_compare(PHP_VERSION, '8.5.0', '>=');
    }

    /**
     * 检测是否支持 clone with 语法 (PHP 8.5+)
     */
    public static function supportsCloneWith(): bool
    {
        return version_compare(PHP_VERSION, '8.5.0', '>=');
    }

    /**
     * 检测是否支持 NoDiscard 属性 (PHP 8.5+)
     */
    public static function supportsNoDiscardAttribute(): bool
    {
        return version_compare(PHP_VERSION, '8.5.0', '>=');
    }

    /**
     * 检测是否支持 URI 扩展 (PHP 8.5+)
     */
    public static function supportsUriExtension(): bool
    {
        return version_compare(PHP_VERSION, '8.5.0', '>=') && extension_loaded('uri');
    }

    /**
     * 检测是否支持 readonly 类 (PHP 8.2+)
     */
    public static function supportsReadonlyClass(): bool
    {
        return version_compare(PHP_VERSION, '8.2.0', '>=');
    }

    /**
     * 检测是否支持枚举 (PHP 8.1+)
     */
    public static function supportsEnum(): bool
    {
        return version_compare(PHP_VERSION, '8.1.0', '>=');
    }

    /**
     * 检测是否支持 never 返回类型 (PHP 8.1+)
     */
    public static function supportsNeverType(): bool
    {
        return version_compare(PHP_VERSION, '8.1.0', '>=');
    }

    /**
     * 检测是否支持 true/false/null 独立类型 (PHP 8.2+)
     */
    public static function supportsStandaloneTypes(): bool
    {
        return version_compare(PHP_VERSION, '8.2.0', '>=');
    }

    /**
     * 获取当前 PHP 版本信息
     */
    public static function getVersionInfo(): array
    {
        return [
            'version' => PHP_VERSION,
            'major' => PHP_MAJOR_VERSION,
            'minor' => PHP_MINOR_VERSION,
            'release' => PHP_RELEASE_VERSION,
            'features' => [
                'enum' => self::supportsEnum(),
                'readonly_class' => self::supportsReadonlyClass(),
                'never_type' => self::supportsNeverType(),
                'standalone_types' => self::supportsStandaloneTypes(),
                'pipe_operator' => self::supportsPipeOperator(),
                'clone_with' => self::supportsCloneWith(),
                'no_discard' => self::supportsNoDiscardAttribute(),
                'uri_extension' => self::supportsUriExtension(),
            ],
        ];
    }
}
