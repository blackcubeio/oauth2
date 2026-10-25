# Blackcube OAuth2

OAuth2/JWT toolbox with multi-population support based on BShaffer oauth2 server.

[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE.md)
[![Packagist Version](https://img.shields.io/packagist/v/blackcube/oauth2.svg)](https://packagist.org/packages/blackcube/oauth2)

## Installation

```bash
composer require blackcube/oauth2
```

## Based On

- [bshaffer/oauth2-server-php](https://github.com/bshaffer/oauth2-server-php) - OAuth2 engine ([documentation](https://bshaffer.github.io/oauth2-server-php-docs/))
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
    'blackcube/oauth2' => [
        'name' => 'admin',
        'issuer' => 'myapp-admin',
        'audience' => 'myapi',
        'userQueryClass' => \App\Oauth2\AdminUser::class,
        'clientQueryClass' => \App\Oauth2\AdminClient::class,
        'refreshTokenQueryClass' => \App\Oauth2\AdminRefreshToken::class,
        'cypherKeyQueryClass' => \Blackcube\Oauth2\Jwt\CypherKey::class,
        'algorithm' => 'RS256',
        'rsPublicKey' => '/path/to/config/keys/public.pem',
        'rsPrivateKey' => '/path/to/config/keys/private.pem',
        'hsKey' => '',                   // HS* algorithms only
        'temporaryPath' => null,         // defaults to the system temporary directory
        'accessTokenTtl' => 3600,        // 1h
        'refreshTokenTtl' => 2592000,    // 30 days
        'allowedGrants' => ['password', 'refresh_token'],
    ],
];
```

### di.php

The package does not wire the signing key itself: each population brings its own,
so the definition lives in the application (or in the package that owns the
population).

```php
use Blackcube\Oauth2\Jwt\CypherKey;
use Blackcube\Oauth2\PopulationConfig;

return [
    PopulationConfig::class => [
        'class' => PopulationConfig::class,
        '__construct()' => [
            'name' => $params['blackcube/oauth2']['name'],
            'issuer' => $params['blackcube/oauth2']['issuer'],
            'audience' => $params['blackcube/oauth2']['audience'],
            'userQueryClass' => $params['blackcube/oauth2']['userQueryClass'],
            'clientQueryClass' => $params['blackcube/oauth2']['clientQueryClass'],
            'refreshTokenQueryClass' => $params['blackcube/oauth2']['refreshTokenQueryClass'],
            'cypherKeyQueryClass' => $params['blackcube/oauth2']['cypherKeyQueryClass'],
            'algorithm' => $params['blackcube/oauth2']['algorithm'],
            'accessTokenTtl' => $params['blackcube/oauth2']['accessTokenTtl'],
            'refreshTokenTtl' => $params['blackcube/oauth2']['refreshTokenTtl'],
            'allowedGrants' => $params['blackcube/oauth2']['allowedGrants'],
        ],
    ],

    CypherKey::class => [
        'class' => CypherKey::class,
        '__construct()' => [
            'id' => $params['blackcube/oauth2']['issuer'],
            'rsPublicKey' => $params['blackcube/oauth2']['rsPublicKey'],
            'rsPrivateKey' => $params['blackcube/oauth2']['rsPrivateKey'],
            'hsKey' => $params['blackcube/oauth2']['hsKey'],
            'algorithm' => $params['blackcube/oauth2']['algorithm'],
            'temporaryPath' => $params['blackcube/oauth2']['temporaryPath'],
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

`CypherKeyInterface` is the one interface the package already implements: `CypherKey` reads the `RS*` keys from two files and builds them when they are missing, and carries the `HS*` secret as it is given, see [Key Generation](#key-generation).

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

### Automatic generation (CypherKey)

`CypherKey` is the implementation of `CypherKeyInterface` shipped with the
package. With an `RS*` algorithm it holds the **paths** of the key files, not
their content: a key is read when a token is signed or verified, and the pair is
built right there when it is missing, so a fresh installation needs no manual
step. With an `HS*` one it holds the shared secret itself.

```php
// params.php
'blackcube/oauth2' => [
    'issuer' => 'myapp-admin',
    'cypherKeyQueryClass' => \Blackcube\Oauth2\Jwt\CypherKey::class,
    'algorithm' => 'RS256',
    'rsPublicKey' => dirname(__DIR__, 2).'/config/keys/public.pem',
    'rsPrivateKey' => dirname(__DIR__, 2).'/config/keys/private.pem',
    'hsKey' => '',
    'temporaryPath' => null,
],
```

Both keys are rebuilt together as soon as one is missing: an orphan public key
glued back to a new private one would sign tokens nobody could verify.
Generation covers the `RS*` algorithms; any other one is refused rather than
turned into an RSA pair under a name it does not have.

With an `HS*` algorithm nothing is read from disk and nothing is built:
`hsKey` carries the shared secret itself, and the application provides it -
`openssl rand -base64 32` gives a fitting one. Signature and verification use
that same string, so `getPublicKey()` hands it out too: `Oauth2Storage` is asked
for a public key whatever the algorithm, and the decoder needs the secret to
check an `HS*` token. An empty `hsKey` raises a `RuntimeException` instead of
signing with an empty string.

Each file is written to `temporaryPath` first, then `rename()`d into place: the
final file shows up in one go, so a concurrent request never reads a half written
key, and no leftover sits next to the keys. A failed move raises a
`RuntimeException` naming both paths.

`temporaryPath` defaults to `sys_get_temp_dir()`. Point it at a directory sitting
next to the keys when the system temporary directory lives on another filesystem:
the kernel cannot move a file across filesystems, so PHP falls back to a copy and
the key stops showing up in one go.

## Middleware Usage

```php
use Blackcube\Oauth2\Middlewares\JwtValidatorMiddleware;

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
