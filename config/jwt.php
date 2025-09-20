<?php

return [
    'defaults' => [
        'guard' => 'api',
        'provider' => 'users',
    ],

    'guards' => [
        'api' => [
            'driver' => 'sso', // 或 'mlo' 用于多点登录
            'provider' => 'users',
            'storage' => 'redis', // redis, memory, null
            'blacklist_enabled' => true,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160, // 分钟（2周）
            'ttl' => 1440, // 分钟（24小时）
            'algo' => 'HS256', // HS256 或 RS256
            'secret' => env('JWT_SECRET', 'your-secret-key'),
            'public_key' => env('JWT_PUBLIC_KEY_PATH', ''),
            'private_key' => env('JWT_PRIVATE_KEY_PATH', ''),
        ],
        
        'web' => [
            'driver' => 'mlo', // web端允许多点登录
            'provider' => 'users',
            'storage' => 'redis',
            'blacklist_enabled' => true,
            'refresh_enabled' => true,
            'refresh_ttl' => 20160,
            'ttl' => 1440,
            'algo' => 'HS256',
            'secret' => env('JWT_SECRET', 'your-secret-key'),
        ],
    ],

    'platforms' => [
        'web', 'h5', 'pc', 'app', 'wx_mini', 'ali_mini', 'tt_mini'
    ],

    'storage' => [
        'redis' => [
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'port' => env('REDIS_PORT', 6379),
            'password' => env('REDIS_PASSWORD', null),
            'database' => env('REDIS_DB', 0),
            'prefix' => 'kode:jwt:',
        ],
        'memory' => [
            'limit' => 10000, // 最大缓存数量
        ]
    ],

    'events' => [
        'enabled' => true,
        'listeners' => [
            // \App\Listeners\OnTokenIssued::class,
            // \App\Listeners\OnTokenRevoked::class,
        ]
    ]
];