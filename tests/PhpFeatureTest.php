<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Support\PhpFeature;
use PHPUnit\Framework\TestCase;

final class PhpFeatureTest extends TestCase
{
    public function testSupportsEnum(): void
    {
        self::assertTrue(PhpFeature::supportsEnum());
    }

    public function testSupportsNeverType(): void
    {
        self::assertTrue(PhpFeature::supportsNeverType());
    }

    public function testSupportsReadonlyClass(): void
    {
        $result = PhpFeature::supportsReadonlyClass();
        self::assertIsBool($result);
    }

    public function testSupportsStandaloneTypes(): void
    {
        $result = PhpFeature::supportsStandaloneTypes();
        self::assertIsBool($result);
    }

    public function testSupportsPipeOperator(): void
    {
        $result = PhpFeature::supportsPipeOperator();
        self::assertIsBool($result);
    }

    public function testSupportsCloneWith(): void
    {
        $result = PhpFeature::supportsCloneWith();
        self::assertIsBool($result);
    }

    public function testSupportsNoDiscardAttribute(): void
    {
        $result = PhpFeature::supportsNoDiscardAttribute();
        self::assertIsBool($result);
    }

    public function testSupportsUriExtension(): void
    {
        $result = PhpFeature::supportsUriExtension();
        self::assertIsBool($result);
    }

    public function testGetVersionInfo(): void
    {
        $info = PhpFeature::getVersionInfo();

        self::assertArrayHasKey('version', $info);
        self::assertArrayHasKey('major', $info);
        self::assertArrayHasKey('minor', $info);
        self::assertArrayHasKey('release', $info);
        self::assertArrayHasKey('features', $info);

        self::assertSame(PHP_VERSION, $info['version']);
        self::assertSame(PHP_MAJOR_VERSION, $info['major']);
        self::assertSame(PHP_MINOR_VERSION, $info['minor']);
        self::assertSame(PHP_RELEASE_VERSION, $info['release']);

        self::assertArrayHasKey('enum', $info['features']);
        self::assertArrayHasKey('readonly_class', $info['features']);
        self::assertArrayHasKey('never_type', $info['features']);
        self::assertArrayHasKey('pipe_operator', $info['features']);
        self::assertArrayHasKey('clone_with', $info['features']);
    }
}
