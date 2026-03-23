<?php

declare(strict_types=1);

namespace Kode\Jwt\Console;

use Kode\Jwt\KodeJwt;
use Kode\Jwt\Token\Payload;

/**
 * Token 管理 CLI 命令
 *
 * 提供生成、验证、刷新、注销 Token 的命令行工具
 */
class TokenCommand
{
    protected string $signature = 'jwt:token';

    protected string $description = '管理 JWT Token';

    protected string $basePath;

    protected string $action = '';

    protected ?string $token = null;

    protected ?string $configPath = null;

    protected array $payload = [];

    protected string $guard = 'api';

    public function __construct(?string $basePath = null)
    {
        $this->basePath = $basePath ?? getcwd();
    }

    /**
     * 执行命令
     */
    public function handle(array $args = []): int
    {
        $this->parseArgs($args);

        if ($this->configPath) {
            KodeJwt::loadConfigFromFile($this->configPath);
        }

        return match ($this->action) {
            'generate', 'gen', 'create' => $this->generateToken(),
            'verify', 'validate', 'auth' => $this->verifyToken(),
            'refresh', 'renew' => $this->refreshToken(),
            'invalidate', 'revoke', 'logout' => $this->invalidateToken(),
            'info', 'decode' => $this->showTokenInfo(),
            'help' => $this->showHelp(),
            default => $this->showHelp(),
        };
    }

    /**
     * 解析命令参数
     */
    protected function parseArgs(array $args): void
    {
        $this->action = '';
        $this->token = null;
        $this->configPath = null;
        $this->payload = [];
        $this->guard = 'api';

        foreach ($args as $arg) {
            if (str_starts_with($arg, '--config=')) {
                $this->configPath = substr($arg, 9);
                continue;
            }

            if (str_starts_with($arg, '--guard=')) {
                $this->guard = substr($arg, 8);
                continue;
            }

            if (str_starts_with($arg, '--token=')) {
                $this->token = substr($arg, 8);
                continue;
            }

            if (str_starts_with($arg, '--uid=')) {
                $this->payload['uid'] = substr($arg, 6);
                continue;
            }

            if (str_starts_with($arg, '--username=')) {
                $this->payload['username'] = substr($arg, 11);
                continue;
            }

            if (str_starts_with($arg, '--platform=')) {
                $this->payload['platform'] = substr($arg, 11);
                continue;
            }

            if (str_starts_with($arg, '--roles=')) {
                $this->payload['roles'] = explode(',', substr($arg, 8));
                continue;
            }

            if (str_starts_with($arg, '--perms=')) {
                $this->payload['perms'] = explode(',', substr($arg, 8));
                continue;
            }

            // 识别操作
            $actions = [
                'generate', 'gen', 'create',
                'verify', 'validate', 'auth',
                'refresh', 'renew',
                'invalidate', 'revoke', 'logout',
                'info', 'decode', 'help',
            ];
            if (in_array($arg, $actions, true)) {
                $this->action = $arg;
            }
        }
    }

    /**
     * 生成 Token
     */
    protected function generateToken(): int
    {
        if (empty($this->payload['uid'])) {
            echo "❌ 错误: 必须指定 --uid 参数\n";
            return 1;
        }

        $now = time();
        $ttl = 1440;

        $payload = Payload::create(
            uid: $this->payload['uid'],
            username: $this->payload['username'] ?? 'user',
            platform: $this->payload['platform'] ?? 'cli',
            exp: $now + ($ttl * 60),
            iat: $now,
            jti: 'jwt_' . bin2hex(random_bytes(16)),
            roles: $this->payload['roles'] ?? null,
            perms: $this->payload['perms'] ?? null
        );

        try {
            $result = KodeJwt::issue($payload, $this->guard);

            echo "✅ Token 生成成功:\n\n";
            echo "Token: {$result['token']}\n\n";
            echo "过期时间: {$result['expires_in']} 秒\n";
            echo "刷新 TTL: {$result['refresh_ttl']} 秒\n";

            return 0;
        } catch (\Exception $e) {
            echo "❌ Token 生成失败: {$e->getMessage()}\n";
            return 1;
        }
    }

    /**
     * 验证 Token
     */
    protected function verifyToken(): int
    {
        if ($this->token === null) {
            echo "❌ 错误: 必须指定 --token 参数\n";
            return 1;
        }

        try {
            $payload = KodeJwt::authenticate($this->token, $this->guard);

            echo "✅ Token 验证成功:\n\n";
            echo "用户 ID: {$payload->uid}\n";
            echo "用户名: {$payload->username}\n";
            echo "平台: {$payload->platform}\n";
            echo "过期时间: " . date('Y-m-d H:i:s', $payload->exp) . "\n";
            echo "签发时间: " . date('Y-m-d H:i:s', $payload->iat) . "\n";
            echo "JTI: {$payload->jti}\n";

            if ($payload->roles) {
                echo "角色: " . implode(', ', $payload->roles) . "\n";
            }

            if ($payload->perms) {
                echo "权限: " . implode(', ', $payload->perms) . "\n";
            }

            return 0;
        } catch (\Exception $e) {
            echo "❌ Token 验证失败: {$e->getMessage()}\n";
            return 1;
        }
    }

    /**
     * 刷新 Token
     */
    protected function refreshToken(): int
    {
        if ($this->token === null) {
            echo "❌ 错误: 必须指定 --token 参数\n";
            return 1;
        }

        try {
            $result = KodeJwt::refresh($this->token, $this->guard);

            echo "✅ Token 刷新成功:\n\n";
            echo "新 Token: {$result['token']}\n\n";
            echo "过期时间: {$result['expires_in']} 秒\n";
            echo "刷新 TTL: {$result['refresh_ttl']} 秒\n";

            return 0;
        } catch (\Exception $e) {
            echo "❌ Token 刷新失败: {$e->getMessage()}\n";
            return 1;
        }
    }

    /**
     * 注销 Token
     */
    protected function invalidateToken(): int
    {
        if ($this->token === null) {
            echo "❌ 错误: 必须指定 --token 参数\n";
            return 1;
        }

        try {
            $result = KodeJwt::invalidate($this->token, $this->guard);

            if ($result) {
                echo "✅ Token 已注销\n";
            } else {
                echo "⚠️  Token 注销失败\n";
            }

            return $result ? 0 : 1;
        } catch (\Exception $e) {
            echo "❌ Token 注销失败: {$e->getMessage()}\n";
            return 1;
        }
    }

    /**
     * 显示 Token 信息
     */
    protected function showTokenInfo(): int
    {
        if ($this->token === null) {
            echo "❌ 错误: 必须指定 --token 参数\n";
            return 1;
        }

        $info = KodeJwt::getTokenInfo($this->token, $this->guard);

        if ($info === null) {
            echo "❌ 无法获取 Token 信息\n";
            return 1;
        }

        echo "📋 Token 信息:\n\n";
        foreach ($info as $key => $value) {
            if (is_array($value)) {
                $value = json_encode($value, JSON_UNESCAPED_UNICODE);
            }
            echo "  {$key}: {$value}\n";
        }

        return 0;
    }

    /**
     * 显示帮助信息
     */
    protected function showHelp(): int
    {
        echo "JWT Token 管理工具\n\n";
        echo "用法: php bin/jwt token <操作> [选项]\n\n";
        echo "操作:\n";
        echo "  generate, gen, create    生成新 Token\n";
        echo "  verify, validate, auth   验证 Token\n";
        echo "  refresh, renew           刷新 Token\n";
        echo "  invalidate, revoke       注销 Token\n";
        echo "  info, decode             显示 Token 信息\n";
        echo "  help                     显示帮助信息\n\n";
        echo "选项:\n";
        echo "  --config=<path>          配置文件路径\n";
        echo "  --guard=<name>           守卫名称 (默认: api)\n";
        echo "  --token=<token>          Token 字符串\n";
        echo "  --uid=<id>               用户 ID\n";
        echo "  --username=<name>        用户名\n";
        echo "  --platform=<platform>    平台标识\n";
        echo "  --roles=<role1,role2>    角色列表\n";
        echo "  --perms=<perm1,perm2>    权限列表\n\n";
        echo "示例:\n";
        echo "  php bin/jwt token generate --uid=123 --username=john\n";
        echo "  php bin/jwt token verify --token=eyJ...\n";
        echo "  php bin/jwt token refresh --token=eyJ...\n";
        echo "  php bin/jwt token invalidate --token=eyJ...\n";

        return 0;
    }

    /**
     * 设置基础路径
     */
    public function setBasePath(string $basePath): self
    {
        $this->basePath = $basePath;
        return $this;
    }

    /**
     * 静态运行方法
     */
    public static function run(array $args = [], ?string $basePath = null): int
    {
        $command = new self($basePath);
        return $command->handle($args);
    }
}
