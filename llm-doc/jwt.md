# oauth2 — JWT

## `Jwt\CypherKey` (implements `CypherKeyInterface`)

```php
new CypherKey(
    string $id,
    string $rsPublicKey = '',
    string $rsPrivateKey = '',
    string $hsKey = '',
    string $algorithm = 'RS256',
    ?string $temporaryPath = null,
);
```

| Algorithm | Keys |
|---|---|
| `RS*` | `rsPublicKey` / `rsPrivateKey` = **paths**; files read on every `getPublicKey()` / `getPrivateKey()` |
| `HS*` | `hsKey` = the secret itself; `getPublicKey()` and `getPrivateKey()` both return it |

RS generation (measured):
- One of the two files missing → pair generated on first `get*Key()`, RSA 4096 bits; both files always rebuilt together.
- Directory created `0700`, private key `0600`, public key `0644`.
- Each file written in `temporaryPath` (default `sys_get_temp_dir()`) then `rename()`; temporary directory on another filesystem → copy, the file no longer appears in one go: set `temporaryPath` on the keys' filesystem.

Errors (measured):

| Case | Exception |
|---|---|
| `HS*` without `hsKey` | `RuntimeException` `Algorithm HS256 needs hsKey to be configured.` |
| missing files, algorithm neither `RS*` nor `HS*` | `RuntimeException` `Keys are missing and algorithm ES256 is not supported by the generation: drop them manually.` |

Single instance (measured): the constructor stores the object in `self::$instance`. After two `new CypherKey()`, `queryDefault()` returns the second and `queryById('<first id>')` returns `null`. One key per process = one signing key for every population of the process.

## `Jwt\JwtService`

| Method | Behaviour |
|---|---|
| `encode(CypherKeyInterface $key, string $subject, string $issuer, string $audience, array $scopes, int $ttl): string` | claims `iss`, `aud`, `sub`, `iat`, `exp` (now + `$ttl`), `scopes` |
| `decode(string $token, CypherKeyInterface $key): ?JwtClaims` | checks the **signature only**; wrong key / unreadable → `null`. Measured: an expired token returns its claims. |

- Algorithms: RS256, RS384, RS512, HS256, HS384, HS512. Any other → `InvalidArgumentException` `Unsupported algorithm: X` in `encode()`; `null` in `decode()`.
- After `decode()`, the caller checks `isExpired()`, `iss`, `aud`.

## `Jwt\JwtClaims`

- Readonly: `sub`, `iss`, `aud` (first element if `aud` is an array), `scopes`, `exp`, `iat` (`DateTimeImmutable`).
- `isExpired(): bool` (`exp` in the past), `hasScope(string): bool` (strict).

## `Middlewares\AbstractJwtMiddleware`

| Method (`protected`) | Role |
|---|---|
| `extractBearerToken($request): ?string` | `Authorization: Bearer <token>`, case-insensitive (measured: `bearer` works) |
| `parseTokenClaims(string): ?array` | claims **without any check** (to read `iss` before choosing the key) |
| `validateToken(string, CypherKeyInterface): ?array` | signature + date (`LooseValidAt` with the injected clock); claims as an array (`exp` / `iat` as `DateTimeImmutable`) |
| `buildJwtConfiguration(CypherKeyInterface): Configuration` | signer taken from `static::SIGNERS` |

Constructor: `ClockInterface $clock`.

## `Middlewares\JwtValidatorMiddleware`

```php
new JwtValidatorMiddleware(string $cypherKeyClass, ClockInterface $clock, ResponseFactoryInterface $responseFactory, StreamFactoryInterface $streamFactory);
```

1. Bearer token.
2. `iss` read without check → `$cypherKeyClass::queryById(iss)`.
3. Signature + date validated.
4. Request attributes: `jwt` (claims array), `userId` (`sub`), `population` (`iss`), `scopes`.

`aud` is not checked (measured: a token with `aud` = `any-audience` passes).

Responses (measured), `WWW-Authenticate: Bearer` + JSON body:

| Case | Response |
|---|---|
| no token | 401 `{"error":"unauthorized","error_description":"Missing token"}` |
| expired token, unknown `iss`, wrong signature | 401 `{"error":"unauthorized","error_description":"Invalid token"}` |
