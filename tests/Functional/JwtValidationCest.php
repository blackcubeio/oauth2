<?php

declare(strict_types=1);

namespace Blackcube\Oauth2\Tests\Functional;

use Blackcube\Oauth2\Jwt\JwtClaims;
use Blackcube\Oauth2\Jwt\JwtService;
use Blackcube\Oauth2\Tests\Support\DatabaseCestTrait;
use Blackcube\Oauth2\Tests\Support\FunctionalTester;
use Blackcube\Oauth2\Tests\Support\TestCypherKey;
use DateTimeImmutable;

final class JwtValidationCest
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

    public function testValidJwtIsAccepted(FunctionalTester $I): void
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
        $I->assertEquals('1', $claims->sub);
        $I->assertEquals('test-issuer', $claims->iss);
        $I->assertContains('read', $claims->scopes);
        $I->assertContains('write', $claims->scopes);
    }

    public function testTamperedJwtIsRejected(FunctionalTester $I): void
    {
        $this->ensureTestData();
        $cypherKey = TestCypherKey::queryById('test-issuer');

        $token = $this->ensureJwtService()->encode(
            cypherKey: $cypherKey,
            subject: '1',
            issuer: 'test-issuer',
            audience: 'test-audience',
            scopes: ['read'],
            ttl: 3600
        );

        $parts = explode('.', $token);
        $payload = json_decode(base64_decode($parts[1]), true);
        $payload['sub'] = '999';
        $parts[1] = rtrim(base64_encode(json_encode($payload)), '=');
        $tamperedToken = implode('.', $parts);

        $claims = $this->ensureJwtService()->decode($tamperedToken, $cypherKey);

        $I->assertNull($claims);
    }

    public function testJwtWithWrongKeyIsRejected(FunctionalTester $I): void
    {
        $this->ensureTestData();
        $cypherKey = TestCypherKey::queryById('test-issuer');

        $token = $this->ensureJwtService()->encode(
            cypherKey: $cypherKey,
            subject: '1',
            issuer: 'test-issuer',
            audience: 'test-audience',
            scopes: ['read'],
            ttl: 3600
        );

        $otherKey = openssl_pkey_new(['private_key_bits' => 2048]);
        $otherKeyDetails = openssl_pkey_get_details($otherKey);
        openssl_pkey_export($otherKey, $otherPrivate);

        $wrongCypherKey = new TestCypherKey();
        $wrongCypherKey->setId('wrong-key');
        $wrongCypherKey->setPublicKey($otherKeyDetails['key']);
        $wrongCypherKey->setPrivateKey($otherPrivate);
        $wrongCypherKey->setAlgorithm('RS256');
        $wrongCypherKey->setIsDefault(false);
        $wrongCypherKey->setDateCreate(date('Y-m-d H:i:s'));
        $wrongCypherKey->save();

        $claims = $this->ensureJwtService()->decode($token, $wrongCypherKey);

        $I->assertNull($claims);
    }

    public function testValidTokenIsNotExpired(FunctionalTester $I): void
    {
        $this->ensureTestData();
        $cypherKey = TestCypherKey::queryById('test-issuer');

        $token = $this->ensureJwtService()->encode(
            cypherKey: $cypherKey,
            subject: '1',
            issuer: 'test-issuer',
            audience: 'test-audience',
            scopes: ['read'],
            ttl: 3600
        );

        $claims = $this->ensureJwtService()->decode($token, $cypherKey);

        $I->assertNotNull($claims);
        $I->assertFalse($claims->isExpired());
    }

    public function testExpiredTokenIsDetected(FunctionalTester $I): void
    {
        $expiredClaims = new JwtClaims(
            sub: '1',
            iss: 'test-issuer',
            aud: 'test-audience',
            scopes: ['read'],
            exp: new DateTimeImmutable('-1 hour'),
            iat: new DateTimeImmutable('-2 hours')
        );

        $I->assertTrue($expiredClaims->isExpired());
    }

    public function testFutureTokenIsNotExpired(FunctionalTester $I): void
    {
        $validClaims = new JwtClaims(
            sub: '1',
            iss: 'test-issuer',
            aud: 'test-audience',
            scopes: ['read'],
            exp: new DateTimeImmutable('+1 hour'),
            iat: new DateTimeImmutable()
        );

        $I->assertFalse($validClaims->isExpired());
    }
}
