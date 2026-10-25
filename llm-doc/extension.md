# oauth2 — Extension

## 1. Custom grant

- A class implementing `OAuth2\GrantType\GrantTypeInterface`, passed in `$customGrants` of `Oauth2ServerFactory::create()`; added after the grants of `allowedGrants`.
- Identifier = `getQueryStringIdentifier()` = the `grant_type` sent by the client.
- The identifier must be in `ClientInterface::getAllowedGrants()`: bshaffer checks every grant, custom ones included, with `checkRestrictedGrantType()` (`OAuth2/Controller/TokenController.php:193`).
- Not needed in `PopulationConfig::$allowedGrants`: the factory only reads `password`, `client_credentials`, `authorization_code`, `refresh_token` and ignores any other name.
- Reference: `dboard/src/Services/PasskeyGrant.php` (identifier `passkey`), wired in `dboard/src/Handlers/Authentication/Token.php:98-102`.

## 2. Custom response types

- `$customResponseTypes` of `create()`: `'<type>' => ResponseTypeInterface`.
- `'token'`: replaces the default `ResponseType\JwtAccessToken`.
- `'code'`: enables authorization code issuing; the storage must implement `AuthorizationCodeInterface`.
- Reference: `dboard/src/Services/AddonPopulation.php:101-113`.

## 3. Custom JWT payload

- Extend `ResponseType\JwtAccessToken`, override `createPayload($client_id, $user_id, $scope = null)` (`protected`) starting from `parent::createPayload()`, pass the object as `'token'`.
- Keep `scopes` as an array: `JwtService` and the middlewares read it.

## 4. Extended storage

- Extend `Oauth2Storage` (not `final`) and implement other bshaffer storage interfaces, e.g. `AuthorizationCodeInterface`.
- The parent's properties are `private readonly`, logger included: the subclass keeps its own logger reference.
- Reference: `dboard/src/Oauth2/Oauth2Storage.php`.
- `TokenAction` and `AuthorizeAction` build `new Oauth2Storage(...)` themselves: an extended storage needs an application handler (`use Oauth2RequestTrait`, as `dboard/src/Handlers/Oauth/Token.php`).

## 5. JWT middleware

- Extend `AbstractJwtMiddleware`: `extractBearerToken()`, `parseTokenClaims()`, `validateToken()`, `buildJwtConfiguration()` are `protected`.
- Reference: `dboard/src/Middlewares/JwtAuthMiddleware.php` (cookies, refresh, RBAC).
- `JwtValidatorMiddleware`: `$cypherKeyClass` and `unauthorized()` are `private`; a subclass can only override `process()`.

## 6. Signing key

- `CypherKey`: `isSymmetric()`, `symmetricKey()`, `ensureKeyPair()`, `writeKey()` are `protected`: a subclass can change how keys are stored.
- Another key: implement `CypherKeyInterface` and declare it as `cypherKeyQueryClass`.

## 7. Clock

`ClockInterface` is injected into the middlewares: replaceable (e.g. in tests).

## Not extensible

| Point | Why |
|---|---|
| Revoking an access token | access tokens are never stored |
| `JwtService` algorithms | `SIGNERS` is `private const`, read through `self::`; the middlewares' are extensible (`protected const`, read through `static::`) |
| Key generation | `RS*` only |
| Single `CypherKey` instance | `$instance` is `private static`, read through `self::`: a subclass shares the single instance; `queryById()` / `queryDefault()` know one key |
| `Oauth2RequestTrait` methods | `private`: usable only inside the class that `use`s the trait |
