# Integration

## PSR / generic PHP

Instantiate components manually — no framework required.

### Population configuration

```php
use Blackcube\Oauth2\PopulationConfig;
use Blackcube\Oauth2\Storage\Oauth2Storage;
use Blackcube\Oauth2\Server\Oauth2ServerFactory;

$config = new PopulationConfig(
    name: 'admin',
    issuer: 'myapp-admin',
    audience: 'myapi',
    userQueryClass: App\AdminUser::class,
    clientQueryClass: App\AdminClient::class,
    refreshTokenQueryClass: App\AdminRefreshToken::class,
    cypherKeyQueryClass: App\AdminCypherKey::class,
    accessTokenTtl: 3600,
    refreshTokenTtl: 2592000,
    allowedGrants: ['password', 'refresh_token'],
);

$storage = new Oauth2Storage(
    userClass: $config->userQueryClass,
    clientClass: $config->clientQueryClass,
    refreshTokenClass: $config->refreshTokenQueryClass,
    scopeProvider: new App\MyScopeProvider(),
    cypherKeyClass: $config->cypherKeyQueryClass,
);

// Create BShaffer server with configured grants
$server = Oauth2ServerFactory::create($storage, $config);

// With custom grants
$server = Oauth2ServerFactory::create($storage, $config, [$myCustomGrant]);
```

### JWT validation middleware

```php
use Blackcube\Oauth2\Middlewares\JwtValidatorMiddleware;

$middleware = new JwtValidatorMiddleware(
    cypherKeyClass: App\AdminCypherKey::class,
    clock: new App\SystemClock(),
    responseFactory: $responseFactory,
    streamFactory: $streamFactory,
);

// In your PSR-15 pipeline
$pipeline->pipe($middleware);

// After validation, the request carries:
// $request->getAttribute('userId')     — sub claim
// $request->getAttribute('population') — iss claim
// $request->getAttribute('scopes')     — scopes array
// $request->getAttribute('jwt')        — full claims array
```

### JWT encode/decode

```php
use Blackcube\Oauth2\Jwt\JwtService;

$jwtService = new JwtService();
$cypherKey = App\AdminCypherKey::queryDefault();

// Encode
$token = $jwtService->encode(
    cypherKey: $cypherKey,
    subject: '123',
    issuer: 'myapp-admin',
    audience: 'myapi',
    scopes: ['read', 'write'],
    ttl: 3600,
);

// Decode (returns JwtClaims or null)
$claims = $jwtService->decode($token, $cypherKey);
$claims->sub;              // '123'
$claims->hasScope('read'); // true
$claims->isExpired();      // false
```

## Yii

The package ships with config-plugin support.

### params.php

```php
// config/params.php
return [
    'blackcube/oauth2' => [
        'name' => 'admin',
        'issuer' => 'myapp-admin',
        'audience' => 'myapi',
        'userQueryClass' => \App\Oauth2\AdminUser::class,
        'clientQueryClass' => \App\Oauth2\AdminClient::class,
        'refreshTokenQueryClass' => \App\Oauth2\AdminRefreshToken::class,
        'cypherKeyQueryClass' => \App\Oauth2\AdminCypherKey::class,
        'algorithm' => 'RS256',
        'accessTokenTtl' => 3600,
        'refreshTokenTtl' => 2592000,
        'allowedGrants' => ['password', 'refresh_token'],
    ],
];
```

### DI configuration

```php
// config/common/di.php
use Blackcube\Oauth2\Jwt\JwtService;
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

    JwtService::class => JwtService::class,
];
```

### Route registration

```php
use Blackcube\Oauth2\Handlers\TokenAction;
use Blackcube\Oauth2\Handlers\AuthorizeAction;
use Blackcube\Oauth2\Handlers\RevokeAction;
use Blackcube\Oauth2\Middlewares\JwtValidatorMiddleware;

Route::post('/oauth2/token')->action([TokenAction::class, 'handle']),
Route::get('/oauth2/authorize')->action([AuthorizeAction::class, 'handle']),
Route::post('/oauth2/revoke')->action([RevokeAction::class, 'handle']),

// Protected routes
Route::get('/api/protected')
    ->middleware(JwtValidatorMiddleware::class)
    ->action([ProtectedController::class, 'index']),
```
