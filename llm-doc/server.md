# oauth2 — Server

## `PopulationConfig`

| Field | Default | Read by |
|---|---|---|
| `name` | — | nothing in the package |
| `issuer` | — | `Server` (`issuer`), `iss` claim |
| `audience` | — | `JwtAccessToken`, `aud` claim |
| `userQueryClass`, `clientQueryClass`, `refreshTokenQueryClass`, `cypherKeyQueryClass` | — | `Oauth2Storage` through the handlers (`contracts.md`) |
| `algorithm` | `RS256` | nothing in the package: the algorithm comes from the `CypherKey` |
| `accessTokenTtl` | 3600 | `access_lifetime` |
| `refreshTokenTtl` | 2592000 (30 days) | `refresh_token_lifetime` |
| `allowedGrants` | `['password', 'refresh_token']` | grants added to the server |
| `allowImplicit` | `false` | `allow_implicit` |
| `enforceState` | `true` | `enforce_state` |
| `alwaysIssueNewRefreshToken` | `true` | `always_issue_new_refresh_token` |

The package `di` builds `PopulationConfig` from `params['blackcube/oauth2']` for the first 11 fields; the 3 booleans keep their defaults.

## `Oauth2ServerFactory::create()`

```php
Oauth2ServerFactory::create(
    Oauth2Storage $storage,
    PopulationConfig $config,
    array $customGrants = [],
    array $customResponseTypes = [],
    ?TokenTypeInterface $tokenType = null,
    ?ScopeInterface $scopeUtil = null,
    ?ClientAssertionTypeInterface $clientAssertionType = null,
): \OAuth2\Server
```

- Server options: `use_jwt_access_tokens` always `true`, plus the table above.
- `clientAssertionType` default: `BodyFirstHttpBasic` (`allow_credentials_in_request_body`, `allow_public_clients`).
- `token` response type default: `ResponseType\JwtAccessToken` built with `$config->audience`; kept if given in `$customResponseTypes['token']`.
- Grants, from `allowedGrants`:

| Value | bshaffer grant |
|---|---|
| `password` | `UserCredentials` |
| `client_credentials` | `ClientCredentials` |
| `authorization_code` | `AuthorizationCode`: the storage must implement `AuthorizationCodeInterface`, `Oauth2Storage` does not. Measured: base storage → `TypeError` in `create()`. |
| `refresh_token` | `RefreshToken` (`always_issue_new_refresh_token` = config, `unset_refresh_token_after_use` = `true`) |

- `$customGrants`: added after those of `allowedGrants`.

## Issued tokens (measured)

- Token endpoint response: `access_token`, `expires_in`, `token_type`, `scope`, `refresh_token`.
- JWT claims: `id`, `jti`, `iss` (issuer), `aud` (audience), `sub` (user id), `exp`, `iat`, `token_type`, `scope` (string), `client_id`, `scopes` (array).
- Rotation: every use of a refresh token revokes it (`revoke()`) and issues a new one.

## `Oauth2Storage`

- `new Oauth2Storage(userClass, clientClass, refreshTokenClass, ScopeProviderInterface, cypherKeyClass, ?LoggerInterface)`; no logger → `NullLogger`.
- Access tokens never stored: `getAccessToken()` → `null`, `setAccessToken()` → `true` (`:66-74`).
- bshaffer → contracts mapping: `contracts.md`.

## `BodyFirstHttpBasic`

`client_id` present in the request body → `client_id` / `client_secret` read from the body, the HTTP Basic header is ignored. Otherwise: `HttpBasic` behaviour. Purpose: a token endpoint behind a server-level Basic Auth.

## PSR-15 handlers

| Handler | Dependencies | Behaviour |
|---|---|---|
| `TokenAction` | `PopulationConfig`, `ScopeProviderInterface`, `ResponseFactoryInterface`, `StreamFactoryInterface` | builds storage + server per request, `handleTokenRequest()` |
| `AuthorizeAction` | same | `validateAuthorizeRequest()` only: no consent, no code issued. Without the `authorization_code` grant → 302 `unsupported_response_type` (measured). |
| `RevokeAction` | `PopulationConfig`, the 2 factories, `?LoggerInterface` | see below |

`RevokeAction`:

| Case | Response |
|---|---|
| no `token` | 400 `invalid_request` (measured) |
| `token_type_hint` other than `refresh_token` | 400 `unsupported_token_type` (measured) |
| unknown token | 200 (measured) |
| token found | `revoke()`, 200 |
| exception in `revoke()` | 503 `temporarily_unavailable` |

- One population per handler: the `PopulationConfig` of the container.
- `Oauth2RequestTrait`: PSR-7 → bshaffer request, bshaffer → PSR-7 response. The using class must carry `$this->responseFactory` and `$this->streamFactory`.
- Server params passed as is: without `REQUEST_METHOD`, bshaffer answers 405 (measured).
