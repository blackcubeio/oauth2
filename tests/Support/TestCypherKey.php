<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Tests\Support;

use Blackcube\Oauth2\Interfaces\CypherKeyInterface;
use Yiisoft\ActiveRecord\ActiveRecord;

/**
 * @property string $id
 * @property string $publicKey
 * @property string $privateKey
 * @property string $algorithm
 * @property bool $isDefault
 * @property string $dateCreate
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class TestCypherKey extends ActiveRecord implements CypherKeyInterface
{
    protected string $id = '';
    protected string $publicKey = '';
    protected string $privateKey = '';
    protected string $algorithm = 'RS256';
    protected bool $isDefault = false;
    protected \DateTimeImmutable|string $dateCreate = '';

    public function tableName(): string
    {
        return '{{%testCypherKeys}}';
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    public function setId(string $id): void
    {
        $this->id = $id;
    }

    public function setPublicKey(string $key): void
    {
        $this->publicKey = $key;
    }

    public function setPrivateKey(string $key): void
    {
        $this->privateKey = $key;
    }

    public function setAlgorithm(string $algorithm): void
    {
        $this->algorithm = $algorithm;
    }

    public function setIsDefault(bool $isDefault): void
    {
        $this->isDefault = $isDefault;
    }

    public function setDateCreate(string $date): void
    {
        $this->dateCreate = $date;
    }

    public static function queryById(string $id): ?static
    {
        return static::query()->andWhere(['id' => $id])->one();
    }

    public static function queryDefault(): ?static
    {
        return static::query()->andWhere(['isDefault' => true])->one();
    }
}
