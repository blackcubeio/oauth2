<?php

declare(strict_types=1);

namespace Blackcube\Oauth2\Tests\Support;

use Blackcube\Oauth2\Interfaces\UserInterface;
use Yiisoft\ActiveRecord\ActiveRecord;

/**
 * @property int $id
 * @property string $email
 * @property string $passwordHash
 * @property string $dateCreate
 */
final class TestUser extends ActiveRecord implements UserInterface
{
    protected int $id;
    protected string $email = '';
    protected string $passwordHash = '';
    protected \DateTimeImmutable|string $dateCreate = '';
    protected ?array $restrictedScopes = null;

    public function tableName(): string
    {
        return '{{%testUsers}}';
    }

    public function getId(): string
    {
        return (string) $this->id;
    }

    public function getIdentifier(): string
    {
        return $this->email;
    }

    public function getPasswordHash(): string
    {
        return $this->passwordHash;
    }

    public function getRestrictedScopes(): ?array
    {
        return $this->restrictedScopes;
    }

    public function setRestrictedScopes(?array $scopes): void
    {
        $this->restrictedScopes = $scopes;
    }

    public function setEmail(string $email): void
    {
        $this->email = $email;
    }

    public function setPasswordHash(string $hash): void
    {
        $this->passwordHash = $hash;
    }

    public function setDateCreate(string $date): void
    {
        $this->dateCreate = $date;
    }

    public static function queryById(string $id): ?static
    {
        return static::query()->where(['id' => (int) $id])->one();
    }

    public static function queryByIdentifier(string $identifier): ?static
    {
        return static::query()->where(['email' => $identifier])->one();
    }

    public static function queryByIdentifierAndPassword(string $identifier, string $password): ?static
    {
        $user = static::queryByIdentifier($identifier);

        if ($user === null) {
            return null;
        }

        if (!password_verify($password, $user->getPasswordHash())) {
            return null;
        }

        return $user;
    }
}
