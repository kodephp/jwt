<?php

declare(strict_types=1);

namespace Kode\Jwt\Console;

class KeyGenerateCommand
{
    protected string $signature = 'jwt:key';

    protected string $description = '生成 JWT 密钥';

    protected string $basePath;

    protected bool $forceOverwrite = false;

    protected bool $outputToStdout = false;

    protected string $algo = 'rsa';

    public function __construct(string $basePath = null)
    {
        $this->basePath = $basePath ?? getcwd();
    }

    public function handle(array $args = []): int
    {
        $this->parseArgs($args);

        if ($this->algo === 'rsa') {
            return $this->generateRsaKeys();
        }

        return $this->generateSecret();
    }

    protected function parseArgs(array $args): void
    {
        $this->forceOverwrite = false;
        $this->outputToStdout = false;
        $this->algo = 'rsa';

        foreach ($args as $arg) {
            switch ($arg) {
                case 'rsa':
                    $this->algo = 'rsa';
                    break;
                case 'hmac':
                    $this->algo = 'hmac';
                    break;
                case 'stdout':
                    $this->outputToStdout = true;
                    break;
                case 'file':
                    $this->outputToStdout = false;
                    break;
                case '--force':
                    $this->forceOverwrite = true;
                    break;
            }
        }
    }

    public function generateSecret(): int
    {
        $secret = bin2hex(random_bytes(32));

        if ($this->outputToStdout) {
            echo $secret . "\n";
            return 0;
        }

        $keyDir = $this->getKeyPath();
        if (!is_dir($keyDir)) {
            mkdir($keyDir, 0755, true);
        }

        $secretPath = $keyDir . 'secret';

        if (file_exists($secretPath) && !$this->forceOverwrite) {
            echo "⚠️  HMAC 密钥已存在: {$secretPath}\n";
            echo "   使用 --force 覆盖\n";
            return 0;
        }

        file_put_contents($secretPath, $secret);
        chmod($secretPath, 0600);

        echo "✅ HMAC 密钥已生成: {$secretPath}\n";
        return 0;
    }

    public function generateRsaKeys(): int
    {
        $config = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        $keyPair = openssl_pkey_new($config);

        if (!$keyPair) {
            echo "❌ RSA 密钥生成失败\n";
            return 1;
        }

        openssl_pkey_export($keyPair, $privateKey);
        $publicKey = openssl_pkey_get_details($keyPair)['key'];

        if ($this->outputToStdout) {
            echo "=== RSA PRIVATE KEY ===\n";
            echo $privateKey . "\n";
            echo "=== RSA PUBLIC KEY ===\n";
            echo $publicKey . "\n";
            return 0;
        }

        $keyDir = $this->getKeyPath();
        if (!is_dir($keyDir)) {
            mkdir($keyDir, 0755, true);
        }

        $privatePath = $keyDir . 'private.pem';
        $publicPath = $keyDir . 'public.pem';

        $hasChanges = false;

        if ($this->forceOverwrite || !file_exists($privatePath)) {
            file_put_contents($privatePath, $privateKey);
            chmod($privatePath, 0600);
            $hasChanges = true;
        }

        if ($this->forceOverwrite || !file_exists($publicPath)) {
            file_put_contents($publicPath, $publicKey);
            chmod($publicPath, 0644);
            $hasChanges = true;
        }

        if ($hasChanges) {
            echo "✅ RSA 密钥对已生成:\n";
            echo "   - {$privatePath} (私钥)\n";
            echo "   - {$publicPath} (公钥)\n";
        } else {
            echo "⚠️  RSA 密钥对已存在，使用 --force 覆盖\n";
            echo "   - {$privatePath}\n";
            echo "   - {$publicPath}\n";
        }

        return 0;
    }

    public function getKeyPath(): string
    {
        return $this->basePath . '/storage/keys/';
    }

    public function setBasePath(string $basePath): self
    {
        $this->basePath = $basePath;
        return $this;
    }

    public function setForceOverwrite(bool $force): self
    {
        $this->forceOverwrite = $force;
        return $this;
    }

    public function setOutputToStdout(bool $stdout): self
    {
        $this->outputToStdout = $stdout;
        return $this;
    }

    public function setAlgorithm(string $algo): self
    {
        $this->algo = in_array($algo, ['rsa', 'hmac']) ? $algo : 'rsa';
        return $this;
    }

    public static function run(array $args = [], string $basePath = null): int
    {
        $command = new self($basePath);
        return $command->handle($args);
    }
}
