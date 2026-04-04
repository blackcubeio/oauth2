<?php

declare(strict_types=1);

/**
 * DatabaseCestTrait.php
 *
 * PHP version 8.3+
 *
 * @copyright 2010-2026 Blackcube
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Tests\Support;

use Blackcube\Oauth2\Tests\Support\Migrations\M251222120000CreateTestTables;
use Yiisoft\Db\Connection\ConnectionInterface;
use Yiisoft\Db\Connection\ConnectionProvider;
use Yiisoft\Db\Migration\Informer\NullMigrationInformer;
use Yiisoft\Db\Migration\MigrationBuilder;

/**
 * Trait for Cest classes that need database setup.
 *
 * Lifecycle per Cest:
 * 1. drop + create tables — once before the first test
 * 2. run all tests
 * 3. leave DB as-is
 */
trait DatabaseCestTrait
{
    protected ConnectionInterface $db;

    private static array $setupDone = [];

    public function _before(FunctionalTester $I): void
    {
        $this->initializeDatabase();

        $className = static::class;
        if (!isset(self::$setupDone[$className])) {
            $this->dropTables();
            $this->migrateUp();
            self::$setupDone[$className] = true;
        }
    }

    private function initializeDatabase(): void
    {
        $helper = new MysqlHelper();
        $this->db = $helper->createConnection();
        ConnectionProvider::set($this->db);
    }

    private function dropTables(): void
    {
        $this->db->createCommand('DROP TABLE IF EXISTS `testCypherKeys`')->execute();
        $this->db->createCommand('DROP TABLE IF EXISTS `testRefreshTokens`')->execute();
        $this->db->createCommand('DROP TABLE IF EXISTS `testClients`')->execute();
        $this->db->createCommand('DROP TABLE IF EXISTS `testUsers`')->execute();
    }

    private function migrateUp(): void
    {
        $migration = new M251222120000CreateTestTables();
        $builder = new MigrationBuilder($this->db, new NullMigrationInformer());
        $migration->up($builder);
    }
}
