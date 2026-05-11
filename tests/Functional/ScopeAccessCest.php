<?php

declare(strict_types=1);

namespace Blackcube\Oauth2\Tests\Functional;

use Blackcube\Oauth2\Jwt\JwtService;
use Blackcube\Oauth2\Tests\Support\DatabaseCestTrait;
use Blackcube\Oauth2\Tests\Support\FunctionalTester;
use Blackcube\Oauth2\Tests\Support\TestCypherKey;

final class ScopeAccessCest
{
    use DatabaseCestTrait;

    private ?JwtService $jwtService = null;

    private static bool $dataSeeded = false;

    private function ensureJwtService(): JwtService
    {
        return $this->jwtService ??= new JwtService();
    }

    private function ensureTestData(): void
    {
        if (self::$dataSeeded) {
            return;
        }

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

    public function testTokenWithRequiredScopeAllowsAccess(FunctionalTester $I): void
    {
        $this->ensureTestData();
        $cypherKey = TestCypherKey::queryById('test-issuer');

        $token = $this->ensureJwtService()->encode(
            cypherKey: $cypherKey,
            subject: '1',
            issuer: 'test-issuer',
            audience: 'test-audience',
            scopes: ['read', 'write', 'admin'],
            ttl: 3600
        );

        $claims = $this->ensureJwtService()->decode($token, $cypherKey);

        $I->assertNotNull($claims);
        $I->assertTrue($claims->hasScope('admin'));
    }

    public function testTokenWithoutRequiredScopeDeniesAccess(FunctionalTester $I): void
    {
        $this->ensureTestData();
        $cypherKey = TestCypherKey::queryById('test-issuer');

        $token = $this->ensureJwtService()->encode(
            cypherKey: $cypherKey,
            subject: '1',
            issuer: 'test-issuer',
            audience: 'test-audience',
            scopes: ['read', 'profile'],
            ttl: 3600
        );

        $claims = $this->ensureJwtService()->decode($token, $cypherKey);

        $I->assertNotNull($claims);
        $I->assertFalse($claims->hasScope('admin'));
    }

    public function testMultipleScopesAreCheckedCorrectly(FunctionalTester $I): void
    {
        $this->ensureTestData();
        $cypherKey = TestCypherKey::queryById('test-issuer');

        $token = $this->ensureJwtService()->encode(
            cypherKey: $cypherKey,
            subject: '1',
            issuer: 'test-issuer',
            audience: 'test-audience',
            scopes: ['read', 'write'],
            ttl: 3600
        );

        $claims = $this->ensureJwtService()->decode($token, $cypherKey);

        $I->assertNotNull($claims);

        $required = ['read', 'write'];
        $hasAll = empty(array_diff($required, $claims->scopes));
        $I->assertTrue($hasAll);

        $required = ['read', 'admin'];
        $hasAll = empty(array_diff($required, $claims->scopes));
        $I->assertFalse($hasAll);
    }
}
