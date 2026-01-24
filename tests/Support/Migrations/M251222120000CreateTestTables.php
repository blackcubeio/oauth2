<?php

declare(strict_types=1);

namespace Blackcube\Oauth2\Tests\Support\Migrations;

use Yiisoft\Db\Migration\MigrationBuilder;
use Yiisoft\Db\Migration\RevertibleMigrationInterface;
use Yiisoft\Db\Schema\Column\ColumnBuilder;

final class M251222120000CreateTestTables implements RevertibleMigrationInterface
{
    public function up(MigrationBuilder $b): void
    {
        // Users
        $b->createTable('{{%testUsers}}', [
            'id' => ColumnBuilder::bigPrimaryKey(),
            'email' => ColumnBuilder::string(255)->notNull()->unique(),
            'passwordHash' => ColumnBuilder::string(255)->notNull(),
            'dateCreate' => ColumnBuilder::datetime()->notNull(),
        ]);

        // Clients
        $b->createTable('{{%testClients}}', [
            'id' => ColumnBuilder::string(80)->notNull(),
            'secret' => ColumnBuilder::string(255)->null(),
            'redirectUris' => ColumnBuilder::json()->null(),
            'allowedGrants' => ColumnBuilder::json()->null(),
            'dateCreate' => ColumnBuilder::datetime()->notNull(),
        ]);
        $b->addPrimaryKey('testClients', '{{%testClients}}', ['id']);

        // Refresh tokens
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

        // Cypher keys
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
