# oauth2 — Integration

## 1. What the package provides (Yii config-plugin)

| Group | Content |
|---|---|
| `params` | `blackcube/oauth2`: `name`, `issuer`, `audience`, the 4 `*QueryClass`, `algorithm`, `rsPublicKey`, `rsPrivateKey`, `hsKey`, `temporaryPath`, `accessTokenTtl`, `refreshTokenTtl`, `allowedGrants` |
| `di` | `PopulationConfig` (from `params`, `server.md`), `JwtService`, `ClockInterface` → `SystemClock` |

`rsPublicKey`, `rsPrivateKey`, `hsKey`, `temporaryPath` exist in `params` but no package definition reads them.

## 2. What the application declares

| To declare | Why |
|---|---|
| the 4 classes in `params['blackcube/oauth2']` | they implement the contracts (`contracts.md`) |
| `CypherKey` in `di` | the package does not declare it (example: `dboard/config/common/di/oauth2.php:17-27`) |
| `ScopeProviderInterface` | required by `TokenAction` and `AuthorizeAction` |
| `ResponseFactoryInterface`, `StreamFactoryInterface` (PSR-17) | handlers and middleware |
| routes to `TokenAction` / `RevokeAction` | the package declares no route |

The `CypherKey` must be built before a token is issued: it registers itself only in its constructor, the storage reads it through `queryDefault()`.
- Measured: no `CypherKey` built → `TokenAction` raises the warning `openssl_sign(): Supplied key param cannot be coerced into a private key` then `Exception` `Unable to sign data.`.
- dboard: the key is injected into `DboardConfig` (`DboardConfig.php:33`), which its authentication handlers depend on.

## 3. Multi-population

- Population = `issuer` + `audience` + grants + TTL, carried by a `PopulationConfig`.
- One population (simple case): `TokenAction` / `RevokeAction` receive the container's `PopulationConfig`.
- Several populations: one `PopulationConfig` + `Oauth2Storage` + `Server` per population, built lazily. Reference: `dboard/src/Services/AddonPopulation.php:56-116` (issuer = audience = population name; `Oauth2Storage` extended with `AuthorizationCodeInterface` for `authorization_code`; `Oauth2ServerFactory::create($storage, $config, [], $responseTypes)`).
- One signing key per process (`jwt.md`): `JwtValidatorMiddleware` only accepts tokens whose `iss` equals the `id` of that key. For the other populations: `JwtService::decode()` then check `iss`, `aud`, `isExpired()` yourself. Reference: `dboard/src/Services/AccessTokenValidator.php:43-70`.
