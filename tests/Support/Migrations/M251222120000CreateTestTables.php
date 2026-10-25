<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Tests\Support\Migrations;

use Yiisoft\Db\Migration\MigrationBuilder;
use Yiisoft\Db\Migration\RevertibleMigrationInterface;
use Yiisoft\Db\Schema\Column\ColumnBuilder;

class M251222120000CreateTestTables implements RevertibleMigrationInterface
{
    public function up(MigrationBuilder $b): void
    {
        $b->createTable('{{%testUsers}}', [
            'id' => ColumnBuilder::bigPrimaryKey(),
            'email' => ColumnBuilder::string(255)->notNull()->unique(),
            'passwordHash' => ColumnBuilder::string(255)->notNull(),
            'dateCreate' => ColumnBuilder::datetime()->notNull(),
        ]);

        $b->createTable('{{%testClients}}', [
            'id' => ColumnBuilder::string(80)->notNull(),
            'secret' => ColumnBuilder::string(255)->null(),
            'redirectUris' => ColumnBuilder::json()->null(),
            'allowedGrants' => ColumnBuilder::json()->null(),
            'dateCreate' => ColumnBuilder::datetime()->notNull(),
        ]);
        $b->addPrimaryKey('testClients', '{{%testClients}}', ['id']);

        $b->createTable('{{%testRefreshTokens}}', [
            'token' => ColumnBuilder::string(255)->notNull(),
            'userId' => ColumnBuilder::integer()->notNull(),
            'clientId' => ColumnBuilder::string(80)->notNull(),
            'scopes' => ColumnBuilder::json()->null(),
            'expires' => ColumnBuilder::datetime()->notNull(),
            'revoked' => ColumnBuilder::boolean()->notNull()->defaultValue(false),
            'dateCreate' => ColumnBuilder::datetime()->notNull(),
        ]);
        $b->addPrimaryKey('testRefreshTokens', '{{%testRefreshTokens}}', ['token']);

        $b->createTable('{{%testCypherKeys}}', [
            'id' => ColumnBuilder::string(80)->notNull(),
            'publicKey' => ColumnBuilder::text()->notNull(),
            'privateKey' => ColumnBuilder::text()->notNull(),
            'algorithm' => ColumnBuilder::string(10)->notNull()->defaultValue('RS256'),
            'isDefault' => ColumnBuilder::boolean()->notNull()->defaultValue(false),
            'dateCreate' => ColumnBuilder::datetime()->notNull(),
        ]);
        $b->addPrimaryKey('testCypherKeys', '{{%testCypherKeys}}', ['id']);
    }

    public function down(MigrationBuilder $b): void
    {
        $b->dropTable('{{%testCypherKeys}}');
        $b->dropTable('{{%testRefreshTokens}}');
        $b->dropTable('{{%testClients}}');
        $b->dropTable('{{%testUsers}}');
    }
}
