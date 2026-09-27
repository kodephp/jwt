<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\KodeJwt;
use PHPUnit\Framework\TestCase;

/**
 * 版本常量防漂移：本包 composer.json 带显式 `version` 字段，composer 只认它，
 * 类里的 VERSION 是给它做交叉核对的——发版时漏改一处，这里就拦下来。
 */
final class VersionGuardTest extends TestCase
{
    public function testVersionConstantMatchesComposerManifest(): void
    {
        $manifest = json_decode(
            (string) file_get_contents(__DIR__ . '/../composer.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );

        self::assertSame(
            $manifest['version'],
            KodeJwt::VERSION,
            'src/KodeJwt.php 的 VERSION 与 composer.json 的 version 不一致，发版时漏改了一处'
        );
        self::assertSame(KodeJwt::VERSION, KodeJwt::version(), 'version() 必须回读同一常量');
    }

    /**
     * README 里那几处「当前版本」也必须等于发布版本。
     *
     * 上面那条只核对 composer.json ↔ 类常量，README 那一行没有任何东西读它 ——
     * 实测 v1.14.1 发出去之后 README 头部仍写着 `v1.14.0`，全靠人记。
     * 而排障时人先读的是 README：按 1.14.0 读源码会得出与 1.14.1 相反的结论
     * （`get()` 是否认 LIST 键就是这一档的差别）。
     * 两种失败分开点名：解析不到（标记被改掉/删掉）与版本对不上。
     */
    public function testReadmeVersionClaimsMatchTheRelease(): void
    {
        $markers = [
            'README.md 头部「当前版本」' => [
                __DIR__ . '/../README.md',
                '/当前版本\*{0,2}[：:]\s*`v?(\d+\.\d+\.\d+)`/u',
            ],
            'README.md「版本自述」段' => [
                __DIR__ . '/../README.md',
                '/version\(\)`（当前 `(\d+\.\d+\.\d+)`）/u',
            ],
            'README_EN.md 头部 Current Version' => [
                __DIR__ . '/../README_EN.md',
                '/Current Version\*{0,2}[：:]\s*`v?(\d+\.\d+\.\d+)`/u',
            ],
        ];
        // 三条 pattern 恒带 /u：全角冒号与「（」在字节模式下是三个字节，
        // `[：:]` 只消费其中一个，剩下的字节没人吃 —— 于是「解析不到」，
        // 而解析不到的失败原因会被误读成「标记被删了」。

        foreach ($markers as $label => [$file, $pattern]) {
            $source = (string) file_get_contents($file);
            self::assertMatchesRegularExpression(
                $pattern,
                $source,
                "{$label}：读不到版本自述 —— 标记被改掉或删掉了，这一处从此没人核对"
            );

            preg_match($pattern, $source, $match);
            self::assertSame(
                KodeJwt::VERSION,
                $match[1],
                "{$label} 写的是 {$match[1]}，而本包发布版本是 " . KodeJwt::VERSION
            );
        }
    }
}
