<?php

declare(strict_types=1);

namespace Blackcube\Oauth2\Tests\Functional;

use Blackcube\Oauth2\Jwt\JwtService;
use Blackcube\Oauth2\Tests\Support\FunctionalTester;
use Blackcube\Oauth2\Tests\Support\Migrations\M251222120000CreateTestTables;
use Blackcube\Oauth2\Tests\Support\MysqlHelper;
use Blackcube\Oauth2\Tests\Support\TestCypherKey;
use Yiisoft\Db\Connection\ConnectionInterface;
use Yiisoft\Db\Connection\ConnectionProvider;
use Yiisoft\Db\Migration\Informer\NullMigrationInformer;
use Yiisoft\Db\Migration\MigrationBuilder;

final class ScopeAccessCest
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

    public function testTokenWithRequiredScopeAllowsAccess(FunctionalTester $I): void
    {
        $cypherKey = TestCypherKey::queryById('test-issuer');

        $token = $this->jwtService->encode(
            cypherKey: $cypherKey,
            subject: '1',
            issuer: 'test-issuer',
            audience: 'test-audience',
            scopes: ['read', 'write', 'admin'],
            ttl: 3600
        );

        $claims = $this->jwtService->decode($token, $cypherKey);

        $I->assertNotNull($claims);
        $I->assertTrue($claims->hasScope('admin'));
    }

    public function testTokenWithoutRequiredScopeDeniesAccess(FunctionalTester $I): void
    {
        $cypherKey = TestCypherKey::queryById('test-issuer');

        $token = $this->jwtService->encode(
            cypherKey: $cypherKey,
            subject: '1',
            issuer: 'test-issuer',
            audience: 'test-audience',
            scopes: ['read', 'profile'],
            ttl: 3600
        );

        $claims = $this->jwtService->decode($token, $cypherKey);

        $I->assertNotNull($claims);
        $I->assertFalse($claims->hasScope('admin'));
    }

    public function testMultipleScopesAreCheckedCorrectly(FunctionalTester $I): void
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

        // Has both required scopes
        $required = ['read', 'write'];
        $hasAll = empty(array_diff($required, $claims->scopes));
        $I->assertTrue($hasAll);

        // Does not have 'admin'
        $required = ['read', 'admin'];
        $hasAll = empty(array_diff($required, $claims->scopes));
        $I->assertFalse($hasAll);
    }
}
