<?php

declare(strict_types=1);

namespace Kode\Jwt\Tests;

use Kode\Jwt\Metrics\PrometheusMetrics;
use PHPUnit\Framework\TestCase;

final class PrometheusMetricsTest extends TestCase
{
    private PrometheusMetrics $metrics;

    protected function setUp(): void
    {
        $this->metrics = new PrometheusMetrics('test_jwt');
    }

    public function testRecordTokenIssued(): void
    {
        $this->metrics->recordTokenIssued('api', 'web');

        $array = $this->metrics->toArray();
        self::assertArrayHasKey('counters', $array);
    }

    public function testRecordTokenAuthenticated(): void
    {
        $this->metrics->recordTokenAuthenticated('api');

        $array = $this->metrics->toArray();
        self::assertArrayHasKey('counters', $array);
    }

    public function testRecordTokenRefreshed(): void
    {
        $this->metrics->recordTokenRefreshed('api');

        $array = $this->metrics->toArray();
        self::assertArrayHasKey('counters', $array);
    }

    public function testRecordTokenInvalidated(): void
    {
        $this->metrics->recordTokenInvalidated('api');

        $array = $this->metrics->toArray();
        self::assertArrayHasKey('counters', $array);
    }

    public function testRecordAuthenticationFailure(): void
    {
        $this->metrics->recordAuthenticationFailure('expired', 'api');

        $array = $this->metrics->toArray();
        self::assertArrayHasKey('counters', $array);
    }

    public function testSetActiveTokens(): void
    {
        $this->metrics->setActiveTokens(100, 'api');

        $array = $this->metrics->toArray();
        self::assertArrayHasKey('gauges', $array);
    }

    public function testSetBlacklistedTokens(): void
    {
        $this->metrics->setBlacklistedTokens(10, 'api');

        $array = $this->metrics->toArray();
        self::assertArrayHasKey('gauges', $array);
    }

    public function testRecordOperationDuration(): void
    {
        $this->metrics->recordOperationDuration('authenticate', 0.005);

        $array = $this->metrics->toArray();
        self::assertArrayHasKey('histograms', $array);
    }

    public function testTimeOperation(): void
    {
        $result = $this->metrics->timeOperation('test', function () {
            usleep(1000);
            return 'success';
        });

        self::assertSame('success', $result);

        $array = $this->metrics->toArray();
        self::assertArrayHasKey('histograms', $array);
    }

    public function testExport(): void
    {
        $this->metrics->recordTokenIssued('api', 'web');
        $this->metrics->setActiveTokens(50, 'api');

        $output = $this->metrics->export();

        self::assertStringContainsString('test_jwt_tokens_issued_total', $output);
        self::assertStringContainsString('# HELP', $output);
        self::assertStringContainsString('# TYPE', $output);
    }

    public function testReset(): void
    {
        $this->metrics->recordTokenIssued('api', 'web');
        $this->metrics->setActiveTokens(50, 'api');

        $this->metrics->reset();

        $array = $this->metrics->toArray();
        self::assertArrayHasKey('counters', $array);
        self::assertArrayHasKey('gauges', $array);
    }
}
