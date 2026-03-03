<?php

declare(strict_types=1);

namespace Blackcube\Oauth2\Tests\Functional;

use Blackcube\Oauth2\Jwt\JwtClaims;
use Blackcube\Oauth2\Jwt\JwtService;
use Blackcube\Oauth2\Tests\Support\FunctionalTester;
use DateTimeImmutable;
use Blackcube\Oauth2\Tests\Support\Migrations\M251222120000CreateTestTables;
use Blackcube\Oauth2\Tests\Support\MysqlHelper;
use Blackcube\Oauth2\Tests\Support\TestCypherKey;
use Yiisoft\Db\Connection\ConnectionInterface;
use Yiisoft\Db\Connection\ConnectionProvider;
use Yiisoft\Db\Migration\Informer\NullMigrationInformer;
use Yiisoft\Db\Migration\MigrationBuilder;

final class JwtValidationCest
{
    private ConnectionInterface $db;
    private JwtService $jwtService;

    public function _before(FunctionalTester $I): void
    {
        $helper = new MysqlHelper();
        $this->db = $helper->createConnection();
        ConnectionProvider::set($this->db);

        $this->jwtService = new JwtService();

        // Clean and create tables
        $this->db->createCommand('DROP TABLE IF EXISTS `testCypherKeys`')->execute();
        $this->db->createCommand('DROP TABLE IF EXISTS `testRefreshTokens`')->execute();
        $this->db->createCommand('DROP TABLE IF EXISTS `testClients`')->execute();
        $this->db->createCommand('DROP TABLE IF EXISTS `testUsers`')->execute();

        $migration = new M251222120000CreateTestTables();
        $builder = new MigrationBuilder($this->db, new NullMigrationInformer());
        $migration->up($builder);

        // Seed cypher key
        $cypherKey = new TestCypherKey();
        $cypherKey->setId('test-issuer');
        $cypherKey->setPublicKey(file_get_contents(__DIR__ . '/../keys/public.pem'));
        $cypherKey->setPrivateKey(file_get_contents(__DIR__ . '/../keys/private.pem'));
        $cypherKey->setAlgorithm('RS256');
        $cypherKey->setIsDefault(true);
        $cypherKey->setDateCreate(date('Y-m-d H:i:s'));
        $cypherKey->save();
    }

    public function _after(FunctionalTester $I): void
    {
        $this->db->createCommand('DROP TABLE IF EXISTS `testCypherKeys`')->execute();
        $this->db->createCommand('DROP TABLE IF EXISTS `testRefreshTokens`')->execute();
        $this->db->createCommand('DROP TABLE IF EXISTS `testClients`')->execute();
        $this->db->createCommand('DROP TABLE IF EXISTS `testUsers`')->execute();
    }

    public function testValidJwtIsAccepted(FunctionalTester $I): void
    {
        $cypherKey = TestCypherKey::queryById('test-issuer');

        $token = $this->jwtService->encode(
            cypherKey: $cypherKey,
            subject: '1',
            issuer: 'test-issuer',
            audience: 'test-audience',
            scopes: ['read', 'write'],
            ttl: 3600
        );

        $claims = $this->jwtService->decode($token, $cypherKey);

        $I->assertNotNull($claims);
        $I->assertEquals('1', $claims->sub);
        $I->assertEquals('test-issuer', $claims->iss);
        $I->assertContains('read', $claims->scopes);
        $I->assertContains('write', $claims->scopes);
    }

    public function testTamperedJwtIsRejected(FunctionalTester $I): void
    {
        $cypherKey = TestCypherKey::queryById('test-issuer');

        $token = $this->jwtService->encode(
            cypherKey: $cypherKey,
            subject: '1',
            issuer: 'test-issuer',
            audience: 'test-audience',
            scopes: ['read'],
            ttl: 3600
        );

        // Tamper with the payload
        $parts = explode('.', $token);
        $payload = json_decode(base64_decode($parts[1]), true);
        $payload['sub'] = '999';
        $parts[1] = rtrim(base64_encode(json_encode($payload)), '=');
        $tamperedToken = implode('.', $parts);

        $claims = $this->jwtService->decode($tamperedToken, $cypherKey);

        $I->assertNull($claims);
    }

    public function testJwtWithWrongKeyIsRejected(FunctionalTester $I): void
    {
        $cypherKey = TestCypherKey::queryById('test-issuer');

        $token = $this->jwtService->encode(
            cypherKey: $cypherKey,
            subject: '1',
            issuer: 'test-issuer',
            audience: 'test-audience',
            scopes: ['read'],
            ttl: 3600
        );

        // Create a different key
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

        $claims = $this->jwtService->decode($token, $wrongCypherKey);

        $I->assertNull($claims);
    }

    public function testValidTokenIsNotExpired(FunctionalTester $I): void
    {
        $cypherKey = TestCypherKey::queryById('test-issuer');

        $token = $this->jwtService->encode(
            cypherKey: $cypherKey,
            subject: '1',
            issuer: 'test-issuer',
            audience: 'test-audience',
            scopes: ['read'],
            ttl: 3600
        );

        $claims = $this->jwtService->decode($token, $cypherKey);

        $I->assertNotNull($claims);
        $I->assertFalse($claims->isExpired());
    }

    public function testExpiredTokenIsDetected(FunctionalTester $I): void
    {
        // Create a JwtClaims with an expiration in the past
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
        // Create a JwtClaims with an expiration in the future
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
