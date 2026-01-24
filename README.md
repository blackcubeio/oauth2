# Blackcube Yii3 OAuth2

PHP 8.3+ OAuth2/JWT toolbox for Yii3 framework with multi-population support based on BShaffer oauth2 server.

[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE.md)
[![PHP Version](https://img.shields.io/badge/php-8.3%2B-blue.svg)](https://php.net)
[![Packagist Version](https://img.shields.io/packagist/v/blackcube/yii-oauth2.svg)](https://packagist.org/packages/blackcube/yii-oauth2)

## Installation

```bash
composer require blackcube/yii-oauth2
```

## Requirements

- PHP >= 8.3

## Based On

- [bshaffer/oauth2-server-php](https://github.com/bshaffer/oauth2-server-php) - OAuth2 engine
- [lcobucci/jwt](https://github.com/lcobucci/jwt) - JWT handling

## Philosophy

This package is a toolbox, not a turnkey solution. It provides interfaces and tools, never concrete implementations. The application that integrates it decides everything: storage, tables, business logic, routes.

**Principles:**

- Zero imposed tables
- Zero imposed storage (no MySQL/Redis in the package)
- Multi-population support (admin ≠ customer in the same app)
- DRY: scopes can be derived from an existing system (RBAC, config, API...)

## Configuration

### params.php

```php
return [
    'blackcube/yii-oauth2' => [
        'algorithm' => 'RS256',
        'accessTokenTtl' => 3600,        // 1h
        'refreshTokenTtl' => 2592000,    // 30 days

        'populations' => [
            'admin' => [
                'algorithm' => 'RS512',      // Override base
                'accessTokenTtl' => 7200,    // 2h for admin
                'issuer' => 'myapp-admin',
                'audience' => 'myapi',

                // Entity classes (your app provides these)
                'userClass' => \App\Oauth2\Admin\AdminUser::class,
                'clientClass' => \App\Oauth2\Admin\AdminClient::class,
                'refreshTokenClass' => \App\Oauth2\Admin\AdminRefreshToken::class,
                'scopeProvider' => \App\Oauth2\Admin\RbacScopeProvider::class,
                'cypherKeyClass' => \App\Oauth2\Admin\AdminCypherKey::class,

                // Routes
                'routes' => [
                    'token' => [
                        'pattern' => '/oauth2/admin/token',
                        'methods' => ['POST'],
                    ],
                    'revoke' => [
                        'pattern' => '/oauth2/admin/revoke',
                        'methods' => ['POST'],
                    ],
                ],
            ],

            'customer' => [
                'issuer' => 'myapp-customer',
                'audience' => 'shop',
                'userClass' => \App\Oauth2\Customer\CustomerUser::class,
                'clientClass' => \App\Oauth2\Customer\CustomerClient::class,
                'refreshTokenClass' => \App\Oauth2\Customer\CustomerRefreshToken::class,
                'scopeProvider' => \App\Oauth2\Customer\CustomerScopeProvider::class,
                'cypherKeyClass' => \App\Oauth2\Customer\CustomerCypherKey::class,
                'routes' => [
                    'token' => [
                        'pattern' => '/oauth2/token',
                        'methods' => ['POST'],
                    ],
                ],
                'allowedGrants' => ['password', 'refresh_token'],
            ],
        ],
    ],
];
```

## Interfaces to Implement

Your application must provide implementations for these interfaces per population:

| Interface | Purpose |
|-----------|---------|
| `UserInterface` | User entity with getId, getIdentifier, queryById, queryByIdentifier, queryByIdentifierAndPassword |
| `ClientInterface` | OAuth2 client entity with getId, getSecret, queryById, validateSecret |
| `RefreshTokenInterface` | Refresh token entity with save, revoke, queryByToken |
| `ScopeProviderInterface` | Available scopes, scopes per client |
| `CypherKeyInterface` | Signing keys (RSA/HMAC) with queryById, queryDefault |

## Supported Grants

| Grant | Usage |
|-------|-------|
| password | User login (mobile, SPA legacy) |
| client_credentials | Service to Service (Node → PHP) |
| authorization_code + PKCE | Mobile, modern SPAs |
| refresh_token | Token renewal |

## JWT Claims

```json
{
    "sub": "123",
    "iss": "myapp-admin",
    "aud": "myapi",
    "exp": 1234567890,
    "iat": 1234567800,
    "scopes": ["category", "node", "order"]
}
```

| Claim | Description |
|-------|-------------|
| sub | Subject - User ID |
| iss | Issuer - Identifies the population |
| aud | Audience - Token target |
| exp | Expiration timestamp |
| iat | Issued at timestamp |
| scopes | Granted scopes |

## Algorithms

| Algorithm | Type | Usage |
|-----------|------|-------|
| RS256 | Asymmetric | **Default** - Multi-services |
| RS384 | Asymmetric | More secure than RS256 |
| RS512 | Asymmetric | Maximum security |
| HS256 | Symmetric | Simple, shared secret |
| HS384 | Symmetric | More secure than HS256 |
| HS512 | Symmetric | Maximum symmetric security |

**Recommendation:** RS256/RS384/RS512 if multiple services validate tokens. HS* only if everything stays in the same PHP process.

## Key Generation

### RSA (RS*)

```bash
# RS256/RS384/RS512 - 2048 bits key (minimum)
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# RS512 - 4096 bits key (recommended)
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem
```

### HMAC (HS*)

```bash
# Random 256 bits secret minimum
openssl rand -base64 32 > secret.key
```

## Middleware Usage

```php
use Blackcube\Oauth2\Middleware\JwtValidatorMiddleware;

// In your route configuration
Route::get('/api/protected')
    ->middleware(JwtValidatorMiddleware::class)
    ->action([ProtectedController::class, 'index']);
```

The middleware injects these attributes into the request:

- `jwt` - Full claims array
- `userId` - Subject (sub claim)
- `population` - Issuer (iss claim)
- `scopes` - Granted scopes array

## What This Package Does NOT Do

- Impose tables
- Impose storage (MySQL, Redis, etc.)
- Manage RBAC
- Decide routes
- Impose user/client structure
- Manage sessions
- Provide views (login, authorize, etc.)

## License

BSD-3-Clause. See [LICENSE.md](LICENSE.md).

## Author

Philippe Gaultier <philippe@blackcube.io>