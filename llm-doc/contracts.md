# oauth2 — Contracts

The 4 classes of `PopulationConfig` are class-strings: the package calls their static methods or instantiates them. `ScopeProviderInterface` is an instance (injected into the handlers and into `Oauth2Storage`).

## `UserInterface` (`userQueryClass`)

| Method | Called by | Expected |
|---|---|---|
| `static queryByIdentifierAndPassword(string $identifier, string $password): ?static` | `Oauth2Storage::checkUserCredentials()` (`:216`), `password` grant | `null` = wrong credentials → grant refused |
| `static queryByIdentifier(string $identifier): ?static` | `Oauth2Storage::getUserDetails()` (`:222`) | the user, or `null` |
| `getId(): string` | `getUserDetails()` → `user_id` (`:226`) | becomes the JWT `sub` claim |
| `static queryById(string $id): ?static` | not called by the package | — |
| `getIdentifier(): string` | not called by the package | — |
| `getRestrictedScopes(): ?array` / `setRestrictedScopes(?array)` | not called by the package | — |

## `ClientInterface` (`clientQueryClass`)

| Method | Called by | Expected |
|---|---|---|
| `static queryById(string $clientId): ?static` | every client lookup of `Oauth2Storage` (`:79`, `101`, `113`, `128`) | `null` = unknown client |
| `getId(): string`, `getSecret(): ?string` | `getClientDetails()` (`:83-84`) | — |
| `getRedirectUris(): array` | `getClientDetails()`, joined with spaces (`:85`) | — |
| `getAllowedGrants(): array` | `getClientDetails()` (`:86`), `checkRestrictedGrantType()` (`:104`) | grants allowed **for this client** |
| `isPublic(): bool` | `checkClientCredentials()` (`:116`), `isPublicClient()` (`:130`) | `true` = accepted without a secret |
| `validateSecret(string $secret): bool` | `checkClientCredentials()` for a non-public client (`:119`) | — |

Grants are filtered twice: `PopulationConfig::$allowedGrants` (grants the server accepts) AND `ClientInterface::getAllowedGrants()` (grants of this client). Both must allow it.

## `RefreshTokenInterface` (`refreshTokenQueryClass`)

| Method | Called by | Expected |
|---|---|---|
| no-argument constructor | `new $this->refreshTokenClass()` (`Oauth2Storage.php:171`) | the class must be instantiable without arguments |
| `setToken()`, `setClientId()`, `setUserId()`, `setExpires(DateTimeImmutable)`, `setScopesFromString(?string)`, `setRevoked(false)`, `save()` | `setRefreshToken()` (`:171-181`) | an exception in `save()` is logged, the grant fails |
| `static queryByToken(string $token): ?static` | `getRefreshToken()` (`:138`), `unsetRefreshToken()` (`:197`), `RevokeAction` | — |
| `isRevoked(): bool` | `getRefreshToken()` (`:142`) | revoked = treated as not found |
| `getToken()`, `getClientId()`, `getUserId()`, `getExpires()`, `getScopes()` | `getRefreshToken()` (`:150-156`) | `getScopes()` joined with spaces |
| `revoke(): void` | `unsetRefreshToken()` (`:201`, after use: `unset_refresh_token_after_use`), `RevokeAction` | marks the token revoked |

## `CypherKeyInterface` (`cypherKeyQueryClass`)

| Method | Called by | Expected |
|---|---|---|
| `static queryDefault(): ?static` | `Oauth2Storage::getPublicKey()`, `getPrivateKey()`, `getEncryptionAlgorithm()` (`:261-277`) | the **signing** key; `null` → algorithm falls back to `RS256`, keys `null` |
| `static queryById(string $id): ?static` | `JwtValidatorMiddleware` with `id` = `iss` claim (`:58`) | the **verification** key of the population |
| `getId(): string` | compared with `iss` | equal to the population `issuer` |
| `getPrivateKey(): string`, `getPublicKey(): string` | storage (signing), `JwtService` and middlewares (verification) | HS: both return the same secret |
| `getAlgorithm(): string` | storage, `JwtService`, middlewares | RS256, RS384, RS512, HS256, HS384, HS512 |

Package implementation: `Jwt\CypherKey` (`jwt.md`).

## `ScopeProviderInterface` (instance)

| Method | Called by | Expected |
|---|---|---|
| `scopeExists(string $scope): bool` | `Oauth2Storage::scopeExists()`, scope by scope, all must exist (`:234-246`) | — |
| `scopesForClient(string $clientId): array` | `getClientScope()` (`:95`) | scopes the client may request |
| `defaultScopesForClient(string $clientId): array` | `getDefaultScope()` (`:252`), when no scope is requested | `[]` → token without scope |
| `getAvailableScopes(): array` | not called by the package | — |

`ScopeProviderInterface` is not declared by the package `di`: the application declares it (`TokenAction` and `AuthorizeAction` require it).
