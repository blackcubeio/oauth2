<?php

declare(strict_types=1);

namespace Blackcube\Oauth2\Tests\Functional;

use Blackcube\Oauth2\PopulationConfig;
use Blackcube\Oauth2\Server\Oauth2ServerFactory;
use Blackcube\Oauth2\Storage\Oauth2Storage;
use Blackcube\Oauth2\Tests\Support\DatabaseCestTrait;
use Blackcube\Oauth2\Tests\Support\FunctionalTester;
use Blackcube\Oauth2\Tests\Support\TestClient;
use Blackcube\Oauth2\Tests\Support\TestCypherKey;
use Blackcube\Oauth2\Tests\Support\TestRefreshToken;
use Blackcube\Oauth2\Tests\Support\TestScopeProvider;
use Blackcube\Oauth2\Tests\Support\TestUser;
use OAuth2\Request as Oauth2Request;
use OAuth2\Response as Oauth2Response;

final class PasswordGrantCest
{
    use DatabaseCestTrait;

    private static bool $dataSeeded = false;

    private function ensureTestData(): void
    {
        if (self::$dataSeeded) {
            return;
        }

        $user = new TestUser();
        $user->setEmail('admin@example.com');
        $user->setPasswordHash(password_hash('secret123', PASSWORD_DEFAULT));
        $user->setDateCreate(date('Y-m-d H:i:s'));
        $user->save();

        $client = new TestClient();
        $client->setId('test-app');
        $client->setSecret('client-secret');
        $client->setAllowedGrants(['password', 'refresh_token']);
        $client->setDateCreate(date('Y-m-d H:i:s'));
        $client->save();

        $cypherKey = new TestCypherKey();
        $cypherKey->setId('test-issuer');
        $cypherKey->setPublicKey(file_get_contents(__DIR__ . '/../keys/public.pem'));
        $cypherKey->setPrivateKey(file_get_contents(__DIR__ . '/../keys/private.pem'));
        $cypherKey->setAlgorithm('RS256');
        $cypherKey->setIsDefault(true);
        $cypherKey->setDateCreate(date('Y-m-d H:i:s'));
        $cypherKey->save();

        self::$dataSeeded = true;
    }

    public function testLoginWithValidCredentialsReturnsTokens(FunctionalTester $I): void
    {
        $this->ensureTestData();

        $config = new PopulationConfig(
            name: 'test',
            issuer: 'test-issuer',
            audience: 'test-audience',
            userQueryClass: TestUser::class,
            clientQueryClass: TestClient::class,
            refreshTokenQueryClass: TestRefreshToken::class,
            cypherKeyQueryClass: TestCypherKey::class,
            accessTokenTtl: 3600,
            refreshTokenTtl: 86400,
            allowedGrants: ['password', 'refresh_token'],
        );

        $storage = new Oauth2Storage(
            userClass: $config->userQueryClass,
            clientClass: $config->clientQueryClass,
            refreshTokenClass: $config->refreshTokenQueryClass,
            scopeProvider: new TestScopeProvider(),
            cypherKeyClass: $config->cypherKeyQueryClass,
        );

        $server = Oauth2ServerFactory::create($storage, $config);

        $request = new Oauth2Request(
            query: [],
            request: [
                'grant_type' => 'password',
                'username' => 'admin@example.com',
                'password' => 'secret123',
                'client_id' => 'test-app',
                'client_secret' => 'client-secret',
            ],
            attributes: [],
            cookies: [],
            files: [],
            server: ['REQUEST_METHOD' => 'POST']
        );

        $response = new Oauth2Response();
        $server->handleTokenRequest($request, $response);

        $I->assertEquals(200, $response->getStatusCode(), 'Response body: ' . $response->getResponseBody());

        $body = json_decode($response->getResponseBody(), true);
        $I->assertArrayHasKey('access_token', $body);
        $I->assertArrayHasKey('token_type', $body);
        $I->assertEqualsIgnoringCase('Bearer', $body['token_type']);
    }

    public function testLoginWithBadPasswordReturns401(FunctionalTester $I): void
    {
        $this->ensureTestData();

        $config = new PopulationConfig(
            name: 'test',
            issuer: 'test-issuer',
            audience: 'test-audience',
            userQueryClass: TestUser::class,
            clientQueryClass: TestClient::class,
            refreshTokenQueryClass: TestRefreshToken::class,
            cypherKeyQueryClass: TestCypherKey::class,
            accessTokenTtl: 3600,
            allowedGrants: ['password'],
        );

        $storage = new Oauth2Storage(
            userClass: $config->userQueryClass,
            clientClass: $config->clientQueryClass,
            refreshTokenClass: $config->refreshTokenQueryClass,
            scopeProvider: new TestScopeProvider(),
            cypherKeyClass: $config->cypherKeyQueryClass,
        );

        $server = Oauth2ServerFactory::create($storage, $config);

        $request = new Oauth2Request(
            query: [],
            request: [
                'grant_type' => 'password',
                'username' => 'admin@example.com',
                'password' => 'wrong-password',
                'client_id' => 'test-app',
                'client_secret' => 'client-secret',
            ],
            attributes: [],
            cookies: [],
            files: [],
            server: ['REQUEST_METHOD' => 'POST']
        );

        $response = new Oauth2Response();
        $server->handleTokenRequest($request, $response);

        $I->assertEquals(401, $response->getStatusCode());
    }

    public function testLoginWithUnknownUserReturns401(FunctionalTester $I): void
    {
        $this->ensureTestData();

        $config = new PopulationConfig(
            name: 'test',
            issuer: 'test-issuer',
            audience: 'test-audience',
            userQueryClass: TestUser::class,
            clientQueryClass: TestClient::class,
            refreshTokenQueryClass: TestRefreshToken::class,
            cypherKeyQueryClass: TestCypherKey::class,
            accessTokenTtl: 3600,
            allowedGrants: ['password'],
        );

        $storage = new Oauth2Storage(
            userClass: $config->userQueryClass,
            clientClass: $config->clientQueryClass,
            refreshTokenClass: $config->refreshTokenQueryClass,
            scopeProvider: new TestScopeProvider(),
            cypherKeyClass: $config->cypherKeyQueryClass,
        );

        $server = Oauth2ServerFactory::create($storage, $config);

        $request = new Oauth2Request(
            query: [],
            request: [
                'grant_type' => 'password',
                'username' => 'unknown@example.com',
                'password' => 'whatever',
                'client_id' => 'test-app',
                'client_secret' => 'client-secret',
            ],
            attributes: [],
            cookies: [],
            files: [],
            server: ['REQUEST_METHOD' => 'POST']
        );

        $response = new Oauth2Response();
        $server->handleTokenRequest($request, $response);

        $I->assertEquals(401, $response->getStatusCode());
    }
}
