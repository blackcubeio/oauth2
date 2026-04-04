# API

## Interfaces

Your application must provide implementations for these interfaces per population.

### UserInterface

Resource owner (user) contract.

| Method | Description |
|--------|-------------|
| `getId(): string` | User ID |
| `getIdentifier(): string` | Login identifier (email, username…) |
| `getRestrictedScopes(): ?array` | Per-user scope restrictions |
| `setRestrictedScopes(?array $scopes): void` | Set scope restrictions |
| `queryById(string $id): ?static` | Find user by ID |
| `queryByIdentifier(string $identifier): ?static` | Find user by identifier |
| `queryByIdentifierAndPassword(string $identifier, string $password): ?static` | Authenticate user |

### ClientInterface

OAuth2 client contract.

| Method | Description |
|--------|-------------|
| `getId(): string` | Client ID |
| `getSecret(): ?string` | Client secret (null for public clients) |
| `isPublic(): bool` | Whether the client is public |
| `getRedirectUris(): array` | Allowed redirect URIs |
| `getAllowedGrants(): array` | Allowed grant types |
| `validateSecret(string $secret): bool` | Verify client secret |
| `queryById(string $clientId): ?static` | Find client by ID |

### RefreshTokenInterface

Refresh token contract.

| Method | Description |
|--------|-------------|
| `getToken(): string` | Token string |
| `setToken(string $token): void` | Set token |
| `getUserId(): string` | Owner user ID |
| `setUserId(string $userId): void` | Set owner |
| `getClientId(): string` | Issuing client ID |
| `setClientId(string $clientId): void` | Set client |
| `getScopes(): array` | Granted scopes |
| `setScopesFromString(?string $scope): void` | Set scopes from space-separated string |
| `getExpires(): DateTimeInterface` | Expiration date |
| `setExpires(string $expires): void` | Set expiration |
| `isRevoked(): bool` | Whether token is revoked |
| `setRevoked(bool $revoked): void` | Set revoked flag |
| `save(?array $properties = null): void` | Persist token |
| `revoke(): void` | Revoke token |
| `queryByToken(string $token): ?static` | Find by token string |

### ScopeProviderInterface

Scope provider contract. Scopes can be derived from any existing system (RBAC, config, API…).

| Method | Description |
|--------|-------------|
| `getAvailableScopes(): array` | All available scopes |
| `scopeExists(string $scope): bool` | Check if scope exists |
| `scopesForClient(string $clientId): array` | Scopes available to a client |
| `defaultScopesForClient(string $clientId): array` | Default scopes for a client |

### CypherKeyInterface

JWT signing key contract.

| Method | Description |
|--------|-------------|
| `getId(): string` | Key ID (typically the issuer name) |
| `getPublicKey(): string` | PEM public key |
| `getPrivateKey(): string` | PEM private key (or HMAC secret) |
| `getAlgorithm(): string` | Algorithm (RS256, HS256…) |
| `queryById(string $id): ?static` | Find key by ID |
| `queryDefault(): ?static` | Find the default signing key |

## Classes

### PopulationConfig

Readonly DTO holding the full configuration for one OAuth2 population.

```php
$config = new PopulationConfig(
    name: 'admin',
    issuer: 'myapp-admin',
    audience: 'myapi',
    userQueryClass: AdminUser::class,
    clientQueryClass: AdminClient::class,
    refreshTokenQueryClass: AdminRefreshToken::class,
    cypherKeyQueryClass: AdminCypherKey::class,
    algorithm: 'RS256',
    accessTokenTtl: 3600,
    refreshTokenTtl: 2592000,
    allowedGrants: ['password', 'refresh_token'],
);
```

| Property | Type | Default |
|----------|------|---------|
| `name` | `string` | — |
| `issuer` | `string` | — |
| `audience` | `string` | — |
| `userQueryClass` | `class-string<UserInterface>` | — |
| `clientQueryClass` | `class-string<ClientInterface>` | — |
| `refreshTokenQueryClass` | `class-string<RefreshTokenInterface>` | — |
| `cypherKeyQueryClass` | `class-string<CypherKeyInterface>` | — |
| `algorithm` | `string` | `'RS256'` |
| `accessTokenTtl` | `int` | `3600` |
| `refreshTokenTtl` | `int` | `2592000` |
| `allowedGrants` | `string[]` | `['password', 'refresh_token']` |

### JwtClaims

Readonly DTO representing decoded JWT claims.

```php
$claims->sub;            // '123'
$claims->iss;            // 'myapp-admin'
$claims->aud;            // 'myapi'
$claims->scopes;         // ['read', 'write']
$claims->isExpired();    // false
$claims->hasScope('read'); // true
```

### JwtService

Encodes and decodes JWT tokens using lcobucci/jwt.

```php
$jwtService = new JwtService();

// Encode
$token = $jwtService->encode(
    cypherKey: $cypherKey,
    subject: '123',
    issuer: 'myapp-admin',
    audience: 'myapi',
    scopes: ['read', 'write'],
    ttl: 3600
);

// Decode
$claims = $jwtService->decode($token, $cypherKey);
// Returns JwtClaims or null if invalid/tampered
```

### JwtValidatorMiddleware

PSR-15 middleware that validates Bearer tokens and injects claims into the request.

```php
use Blackcube\Oauth2\Middlewares\JwtValidatorMiddleware;

$middleware = new JwtValidatorMiddleware(
    cypherKeyClass: MyCypherKey::class,
    clock: $psrClock,
    responseFactory: $responseFactory,
    streamFactory: $streamFactory,
);
```

On valid token, the middleware injects these request attributes:

| Attribute | Description |
|-----------|-------------|
| `jwt` | Full claims array |
| `userId` | Subject (`sub` claim) |
| `population` | Issuer (`iss` claim) |
| `scopes` | Granted scopes array |

On missing/invalid token, returns 401 with `WWW-Authenticate: Bearer`.

### Oauth2ServerFactory

Creates a configured BShaffer `OAuth2\Server` from a `PopulationConfig`.

```php
$server = Oauth2ServerFactory::create(
    storage: $oauth2Storage,
    config: $populationConfig,
    customGrants: [],  // optional GrantTypeInterface[]
);
```

Registers grants based on `$config->allowedGrants`: `password`, `client_credentials`, `authorization_code`, `refresh_token`.

For BShaffer server configuration and grant details, see the [bshaffer/oauth2-server-php documentation](https://bshaffer.github.io/oauth2-server-php-docs/).

### Oauth2Storage

Bridge between BShaffer storage interfaces and Blackcube interfaces. Implements:

- `AccessTokenInterface` (JWT — self-contained, no-op)
- `ClientCredentialsInterface`
- `RefreshTokenInterface`
- `UserCredentialsInterface`
- `ScopeInterface`
- `PublicKeyInterface`

```php
$storage = new Oauth2Storage(
    userClass: TestUser::class,
    clientClass: TestClient::class,
    refreshTokenClass: TestRefreshToken::class,
    scopeProvider: new MyScopeProvider(),
    cypherKeyClass: TestCypherKey::class,
    logger: $psrLogger,  // optional
);
```

### Handlers

PSR-15 request handlers for OAuth2 endpoints. All use `Oauth2RequestTrait` to convert PSR-7 ↔ BShaffer requests/responses.

| Handler | Description |
|---------|-------------|
| `TokenAction` | Token endpoint — handles `grant_type` requests |
| `AuthorizeAction` | Authorization endpoint — validates request, consent is app responsibility |
| `RevokeAction` | Token revocation (refresh_token only, RFC 7009) |

### Oauth2RequestTrait

Trait providing PSR-7 ↔ BShaffer request/response conversion. Used by handlers.

## Supported grants

| Grant | Usage |
|-------|-------|
| `password` | User login (mobile, SPA legacy) |
| `client_credentials` | Service to Service (Node → PHP) |
| `authorization_code` | Mobile, modern SPAs (+ PKCE) |
| `refresh_token` | Token renewal |

## Algorithms

| Algorithm | Type | Usage |
|-----------|------|-------|
| RS256 | Asymmetric | **Default** — multi-services |
| RS384 | Asymmetric | More secure than RS256 |
| RS512 | Asymmetric | Maximum security |
| HS256 | Symmetric | Simple, shared secret |
| HS384 | Symmetric | More secure than HS256 |
| HS512 | Symmetric | Maximum symmetric security |

**Recommendation:** RS256/RS384/RS512 if multiple services validate tokens. HS* only if everything stays in the same PHP process.

## Key generation

### RSA (RS*)

```bash
# 2048 bits (minimum)
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# 4096 bits (recommended for RS512)
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem
```

### HMAC (HS*)

```bash
openssl rand -base64 32 > secret.key
```

## JWT claims

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
| `sub` | Subject — User ID |
| `iss` | Issuer — identifies the population |
| `aud` | Audience — token target |
| `exp` | Expiration timestamp |
| `iat` | Issued at timestamp |
| `scopes` | Granted scopes |
