<?php

declare(strict_types=1);

/**
 * JWT 配置文件
 * 由 kode/jwt CLI 工具生成
 *
 * @generated_at 2025-12-30 09:07:01
 */

return [
    'defaults' => [
        'guard' => 'api',         'provider' => 'users',         'platform' => 'web'
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
            'secret' => '49c4160508ad81bb0631b99326cf1da92b49714419b5b8e5e8017613c5c66290',
            'public_key' => <<<'KEY'
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5C8TNNfxUYaJIo2DRoEA
0sheDD7/Yz+++KUg9U+HR7Stg7XSRj/SfmvA/o0jhBaSu+Ed3lO3t+IIXwJ5BBrv
umt8I6Z4y+13VnJQlKmGHfsQF4gZaTqYI8bBR9BwijdHgkhfA/pXheJUWvvwYnyk
yrOImbuMfLpn1VEmldNMYU+pEIiIwk0IcE3ENElPZIUhzQMKlTC5FKuhJdgadiDj
Qqud0uXjQZmunGqdrPKtQigOwtrTBW/s6XICLizP3DAX7OiTBczRUu4GTFjqOLsE
or+Fo7Z9NKUyiLCrwHenzFNAf436G7GWM7SOwmDiaqGaLvZTYmmtDybUUq1Pqu8g
cQIDAQAB
-----END PUBLIC KEY-----

KEY,
            'private_key' => <<<'KEY'
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDkLxM01/FRhoki
jYNGgQDSyF4MPv9jP774pSD1T4dHtK2DtdJGP9J+a8D+jSOEFpK74R3eU7e34ghf
AnkEGu+6a3wjpnjL7XdWclCUqYYd+xAXiBlpOpgjxsFH0HCKN0eCSF8D+leF4lRa
+/BifKTKs4iZu4x8umfVUSaV00xhT6kQiIjCTQhwTcQ0SU9khSHNAwqVMLkUq6El
2Bp2IONCq53S5eNBma6cap2s8q1CKA7C2tMFb+zpcgIuLM/cMBfs6JMFzNFS7gZM
WOo4uwSiv4Wjtn00pTKIsKvAd6fMU0B/jfobsZYztI7CYOJqoZou9lNiaa0PJtRS
rU+q7yBxAgMBAAECggEAG6HjwTN2orkYZER00ECRA/WFsL/0QhBBz8SCGugtlAO6
O3KfldLmv6521EdCih1drujSVXkX4hRk5R8x3nW7RXz8ryiFWlSrGJ8xSOoajAjk
6E9FRyv0U+jJa9PpvPh4GBEsMxl0KIoW+F79Zj/SiPAi1lMS7ovNmn8q8rEq1Qxg
66w0Ek5tl8H+MZf+J+ZKViMK8cQQAgGrh1rL8w8PvGWxtVnnKUAxPwsM356k/Jmc
dLc72bpjZdHim+zd8mkL223NGi7ekK9/Pbn+DmvD0dHJ9YTVcCFGk4DVt51NXXlF
PHqf4yRi/Y5MG5PINYcysw8K9GL530o4QSWWDuqoTQKBgQD90duBDuRYBJKiAseA
b9f15znSPEisfZ+yDu3GZSfDy0fZ5uIssUoHSLJsaPpxwRs9qRq01H9AcdpcL/HV
LQec5mX9jHKCnfDxK3Cdvp5vfnYIZ2aWA+IApWAZzf6dIJwuKoJ2zV4fQ7f8Tnjc
VYhw+aIsikJyECQ+ORmbdLIgvwKBgQDmJNhTq6E0xl08YK6OemM7Qm/CRbwntHbh
QucrDRobTRvZ2CKpvfmppxUw9B4aj+awBCNBvUKGw1qw3qV+uTYxGWbsOTzzgpdC
30HqNbCv15qfOWequ1i21fJ7Hc2/mxqaifNRvuSjE8WCjeMmLbfxUhaoxXJTk/J2
QC7BXfzazwKBgHyzS8p+TIVJydi60NUzHcD8VxYI9BN6rKjIWN1t+Tlid+yAWIJo
n9wwRSip8tFMdFu45xwMgnBg/0znaUK4mtLlBxqok+HEQwnZs7xsWF6inM7ILkhp
o/F5TlufLwZ3bQPpcqt3flSR6qSU0SA/DYejvZ9wVfDAKW5Ak2oizRj1AoGBANAj
zH3HgDEhoZsEeXokF/C1Qiv6M5PZM5bAkh8uZ0j/sMuRHLBVPyF/Gbw/W6Z8NI9F
/rjquOr2bOP/SL9WNDutlJbZoVU96x0wmwV970DpBk8wdKBFdZNN5VIRf03lsebI
EoYA1fji3cMYHbIesPgQXKvgfmg2KpdlrqN1JESjAoGALub4TSESGj4aypSwSa8w
00oC77knWE4u57W7O3hgqOe4KQ2sRqZKLLcjRXNmna1GmJ8HjNl0BrnGA5S4kHMQ
6weZqItCoDkgqVwKJy7U4/DbrjzUR31qHY5qzhBjNbl3mZdTgoYQJ9/1so5Y+YpT
o+3cds+h/0nU41FG4RVC12s=
-----END PRIVATE KEY-----

KEY
        ]
    ],
    'platforms' => [
        0 => 'web',
        1 => 'h5',
        2 => 'pc',
        3 => 'app',
        4 => 'wx_mini',
        5 => 'ali_mini',
        6 => 'tt_mini'
    ],
    'storage' => [
        'redis' => [
            'host' => '127.0.0.1',
            'port' => 6379,
            'password' => '',
            'database' => 0,
            'prefix' => 'kode:jwt:'
        ]
    ]
];
