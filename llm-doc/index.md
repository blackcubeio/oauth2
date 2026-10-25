# blackcube/oauth2 — LLM index

**Role:** multi-population OAuth2/JWT toolbox: token server (bshaffer/oauth2-server-php) wired to the application's classes through 5 contracts, stateless JWT access tokens, persisted refresh tokens, Bearer validation middleware.

## Package card

| | |
|---|---|
| Namespace | `Blackcube\Oauth2` |
| Contracts (implemented by the application) | `UserInterface`, `ClientInterface`, `RefreshTokenInterface`, `CypherKeyInterface`, `ScopeProviderInterface` |
| Server | `PopulationConfig`, `Server\Oauth2ServerFactory`, `Storage\Oauth2Storage`, `ClientAssertion\BodyFirstHttpBasic`, `ResponseType\JwtAccessToken` |
| PSR-15 handlers | `TokenAction`, `AuthorizeAction`, `RevokeAction`, trait `Oauth2RequestTrait` (PSR-7 ↔ bshaffer) |
| JWT | `Jwt\CypherKey`, `Jwt\JwtService`, `Jwt\JwtClaims`, `Middlewares\AbstractJwtMiddleware`, `Middlewares\JwtValidatorMiddleware` |
| Clock | `Clock\SystemClock` (PSR-20) |
| Requires | PHP ^8.2, `bshaffer/oauth2-server-php` ^1.14, `lcobucci/jwt` ^5.6, `psr/http-message` ^2.0, `psr/http-server-handler` ^1.0, `psr/http-server-middleware` ^1.0, `psr/log` ^3.0, `psr/clock` ^1.0. No Blackcube dependency. |
| Yii config | config-plugin: `params` (`blackcube/oauth2`), `di` (`PopulationConfig`, `JwtService`, `ClockInterface` → `SystemClock`) |
| License | BSD-3-Clause |

## Rules

- Population = `iss`: a token belongs to the population of its `iss` claim; the middleware looks the key up with `CypherKey::queryById(iss)` (`JwtValidatorMiddleware.php:57-58`).
- Access tokens = stateless JWTs, never stored (`Oauth2Storage.php:66-74`): only a refresh token can be revoked.
- `JwtService::decode()` only checks the signature: expiry (`JwtClaims::isExpired()`), `iss` and `aud` are checked by the caller.
- The 4 classes of `PopulationConfig` are class-strings: the package calls their static `query*()` methods (`$this->clientClass::queryById()`, `Oauth2Storage.php:79`).
- RS keys: `rsPublicKey` / `rsPrivateKey` are file paths, not contents; generated on first use (RSA 4096) when missing (`CypherKey.php:17-23`, `111-136`).
- `CypherKey` keeps the last instance built: `queryById()` / `queryDefault()` know one key per process (`CypherKey.php:33`, `44`, `165-178`).

## Parts

| File | Content | Read when |
|---|---|---|
| `contracts.md` | The 5 interfaces, method by method: who calls it, what it must return. | before implementing a model |
| `server.md` | `PopulationConfig` (fields, defaults), `Oauth2ServerFactory` (grants from `allowedGrants`, bshaffer options, customisation parameters), `Oauth2Storage` (bshaffer → contracts mapping), `BodyFirstHttpBasic`, the 3 handlers (Authorize only validates; Revoke = refresh token only, unknown → 200), refresh token rotation, claims issued by the default server. | before exposing an endpoint |
| `jwt.md` | `CypherKey` (RS/HS, generation, atomic write, single instance), `JwtService`, `JwtClaims`, middlewares (key by `iss`, `LooseValidAt`, attributes `jwt`/`userId`/`population`/`scopes`, 401 JSON), algorithms RS256/384/512 and HS256/384/512. | before validating a token |
| `integration.md` | Yii: what the package provides and what the application declares (`CypherKey`, `ScopeProviderInterface`, the 4 classes); multi-population: one `PopulationConfig` + storage + server per population (reference: dboard `AddonPopulation`). | before plugging oauth2 in |
| `extension.md` | Custom grants and response types (`create()`), extended storage (e.g. `AuthorizationCodeInterface`), middleware derived from `AbstractJwtMiddleware`, custom JWT payload; what is not extensible. | before extending |
