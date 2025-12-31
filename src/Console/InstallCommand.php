<?php

declare(strict_types=1);

namespace Kode\Jwt\Console;

class InstallCommand
{
    protected string $signature = 'jwt:install';

    protected string $description = '安装 JWT 配置文件并生成密钥';

    protected string $basePath;

    protected array $userConfig = [];

    protected bool $forceOverwrite = false;

    protected string $defaultPlatform = 'web';

    public function __construct(string $basePath = null)
    {
        $this->basePath = $basePath ?? getcwd();
    }

    public function handle(array $args = []): int
    {
        $this->parseOptions($args);

        $action = $this->determineAction($args);

        if ($action === 'config' || $action === 'all') {
            if ($this->publishConfig() !== 0) {
                return 1;
            }
        }

        if ($action === 'key' || $action === 'all') {
            if ($this->generateKeys() !== 0) {
                return 1;
            }
        }

        return 0;
    }

    protected function parseOptions(array $args): void
    {
        foreach ($args as $arg) {
            switch ($arg) {
                case '--force':
                    $this->forceOverwrite = true;
                    break;
                case '--config-only':
                case '--key-only':
                    break;
                default:
                    if (str_starts_with($arg, '--platform=')) {
                        $this->defaultPlatform = substr($arg, 11);
                    }
                    break;
            }
        }
    }

    protected function determineAction(array $args): string
    {
        $hasConfigOnly = in_array('--config-only', $args, true);
        $hasKeyOnly = in_array('--key-only', $args, true);

        if ($hasConfigOnly && $hasKeyOnly) {
            return 'all';
        }

        if ($hasConfigOnly) {
            return 'config';
        }

        if ($hasKeyOnly) {
            return 'key';
        }

        return 'all';
    }

    public function publishConfig(): int
    {
        $configPath = $this->getConfigPath();

        if (file_exists($configPath) && !$this->forceOverwrite) {
            echo "⚠️  配置文件已存在: {$configPath}\n";
            echo "   使用 --force 覆盖现有配置\n";
            return 0;
        }

        $config = $this->generateConfig();

        if (!is_dir(dirname($configPath))) {
            mkdir(dirname($configPath), 0755, true);
        }

        $content = $this->formatConfig($config);

        if (file_put_contents($configPath, $content) === false) {
            echo "❌ 配置文件写入失败: {$configPath}\n";
            return 1;
        }

        echo "✅ 配置文件已发布: {$configPath}\n";
        return 0;
    }

    protected function formatConfig(array $config): string
    {
        $content = "<?php\n\n";
        $content .= "declare(strict_types=1);\n\n";
        $content .= "/**\n";
        $content .= " * JWT 配置文件\n";
        $content .= " * 由 kode/jwt CLI 工具生成\n";
        $content .= " *\n";
        $content .= " * @generated_at {$this->getTimestamp()}\n";
        $content .= " */\n\n";
        $content .= "return " . $this->formatArray($config) . ";\n";

        return $content;
    }

    protected function formatArray(array $config, int $indent = 0): string
    {
        if (empty($config)) {
            return '[]';
        }

        $spaces = str_repeat('    ', $indent);
        $items = [];

        foreach ($config as $key => $value) {
            if (is_string($key)) {
                $formattedKey = is_numeric($key) ? $key : "'{$key}'";
            } else {
                $formattedKey = $key;
            }

            if (is_array($value)) {
                $items[] = "{$spaces}    {$formattedKey} => " . $this->formatArray($value, $indent + 1);
            } elseif (is_bool($value)) {
                $items[] = "{$spaces}    {$formattedKey} => " . ($value ? 'true' : 'false');
            } elseif ($value === null) {
                $items[] = "{$spaces}    {$formattedKey} => null";
            } elseif (is_string($value) && str_starts_with($value, '-----BEGIN')) {
                $items[] = "{$spaces}    {$formattedKey} => <<<'KEY'\n{$value}\nKEY";
            } else {
                $escapedValue = is_string($value) ? "'" . addslashes($value) . "'" : $value;
                $items[] = "{$spaces}    {$formattedKey} => {$escapedValue}";
            }
        }

        if (count($items) <= 3) {
            $inner = implode(", ", $items);
            return "[\n{$inner}\n{$spaces}]";
        }

        return "[\n" . implode(",\n", $items) . "\n{$spaces}]";
    }

    protected function getTimestamp(): string
    {
        return date('Y-m-d H:i:s');
    }

    public function generateConfig(): array
    {
        $config = $this->getDefaultConfig();

        if (!empty($this->userConfig)) {
            $config = $this->mergeConfig($config, $this->userConfig);
        }

        $secret = $this->generateSecret();
        $keyPair = $this->generateRsaKeys();

        if (empty($config['guards']['api']['secret'])) {
            $config['guards']['api']['secret'] = $secret;
        }

        if (empty($config['guards']['api']['private_key']) && !empty($keyPair['private'])) {
            $config['guards']['api']['private_key'] = $keyPair['private'];
        }

        if (empty($config['guards']['api']['public_key']) && !empty($keyPair['public'])) {
            $config['guards']['api']['public_key'] = $keyPair['public'];
        }

        if (!in_array($this->defaultPlatform, $config['platforms'] ?? [])) {
            $config['platforms'] = array_unique(array_merge([$this->defaultPlatform], $config['platforms'] ?? []));
        }

        return $config;
    }

    protected function mergeConfig(array $default, array $user): array
    {
        foreach ($user as $key => $value) {
            if (isset($default[$key]) && is_array($default[$key]) && is_array($value)) {
                $default[$key] = $this->mergeConfig($default[$key], $value);
            } else {
                $default[$key] = $value;
            }
        }
        return $default;
    }

    protected function getDefaultConfig(): array
    {
        return [
            'defaults' => [
                'guard' => 'api',
                'provider' => 'users',
                'platform' => $this->defaultPlatform,
            ],

            'guards' => [
                'api' => [
                    'driver' => 'kode',
                    'provider' => 'users',
                    'storage' => 'redis',
                    'blacklist_enabled' => true,
                    'refresh_enabled' => true,
                    'refresh_ttl' => 20160,
                    'ttl' => 1440,
                    'algo' => 'RS256',
                    'secret' => '',
                    'public_key' => '',
                    'private_key' => '',
                ],
            ],

            'platforms' => [
                $this->defaultPlatform,
                'h5',
                'pc',
                'app',
                'wx_mini',
                'ali_mini',
                'tt_mini',
            ],

            'storage' => [
                'redis' => [
                    'host' => '127.0.0.1',
                    'port' => 6379,
                    'password' => '',
                    'database' => 0,
                    'prefix' => 'kode:jwt:',
                ],
            ],
        ];
    }

    public function generateKeys(): int
    {
        $keyDir = $this->getKeyPath();

        if (!is_dir($keyDir)) {
            mkdir($keyDir, 0755, true);
        }

        $secret = $this->generateSecret();
        $keyPair = $this->generateRsaKeys();

        $secretPath = $keyDir . 'secret';
        $privatePath = $keyDir . 'private.pem';
        $publicPath = $keyDir . 'public.pem';

        $hasChanges = false;

        if ($this->forceOverwrite || !file_exists($secretPath)) {
            file_put_contents($secretPath, $secret);
            $hasChanges = true;
        }

        if ($this->forceOverwrite || !file_exists($privatePath)) {
            file_put_contents($privatePath, $keyPair['private']);
            $hasChanges = true;
        }

        if ($this->forceOverwrite || !file_exists($publicPath)) {
            file_put_contents($publicPath, $keyPair['public']);
            $hasChanges = true;
        }

        if ($hasChanges) {
            echo "✅ 密钥已生成:\n";
            echo "   - {$secretPath} (HMAC 密钥)\n";
            echo "   - {$privatePath} (RSA 私钥)\n";
            echo "   - {$publicPath} (RSA 公钥)\n";
        } else {
            echo "⚠️  密钥已存在，使用 --force 覆盖\n";
            echo "   - {$secretPath}\n";
            echo "   - {$privatePath}\n";
            echo "   - {$publicPath}\n";
        }

        return 0;
    }

    protected function generateSecret(): string
    {
        return bin2hex(random_bytes(32));
    }

    protected function generateRsaKeys(): array
    {
        $config = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        $keyPair = openssl_pkey_new($config);

        if (!$keyPair) {
            throw new \RuntimeException('Failed to generate RSA key pair');
        }

        openssl_pkey_export($keyPair, $privateKey);
        $publicKey = openssl_pkey_get_details($keyPair)['key'];

        return [
            'private' => $privateKey,
            'public' => $publicKey,
        ];
    }

    public function getConfigPath(): string
    {
        return $this->basePath . '/config/jwt.php';
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

    public function setDefaultPlatform(string $platform): self
    {
        $this->defaultPlatform = $platform;
        return $this;
    }

    public static function run(array $args = [], string $basePath = null): int
    {
        $command = new self($basePath);
        return $command->handle($args);
    }
}
