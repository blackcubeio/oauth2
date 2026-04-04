<?php

declare(strict_types=1);

namespace Blackcube\Oauth2\Tests\Support;

use Blackcube\Oauth2\Interfaces\RefreshTokenInterface;
use DateTimeImmutable;
use DateTimeInterface;
use Yiisoft\ActiveRecord\ActiveRecord;

/**
 * @property string $token
 * @property int $userId
 * @property string $clientId
 * @property string|null $scopes
 * @property string $expires
 * @property bool $revoked
 * @property string $dateCreate
 */
final class TestRefreshToken extends ActiveRecord implements RefreshTokenInterface
{
    protected string $token = '';
    protected int $userId = 0;
    protected string $clientId = '';
    protected ?string $scopes = null;
    protected \DateTimeImmutable|string $expires = '';
    protected bool $revoked = false;
    protected \DateTimeImmutable|string $dateCreate = '';

    public function tableName(): string
    {
        return '{{%testRefreshTokens}}';
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function getUserId(): string
    {
        return (string) $this->userId;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getScopes(): array
    {
        if ($this->scopes === null || $this->scopes === '') {
            return [];
        }
        return explode(' ', $this->scopes);
    }

    public function getExpires(): DateTimeInterface
    {
        return new DateTimeImmutable($this->expires);
    }

    public function isRevoked(): bool
    {
        return $this->revoked;
    }

    public function save(?array $properties = null): void
    {
        if ($this->dateCreate === '') {
            $this->dateCreate = date('Y-m-d H:i:s');
        }
        parent::save($properties);
    }

    public function revoke(): void
    {
        $this->revoked = true;
        $this->save();
    }

    public function setToken(string $token): void
    {
        $this->token = $token;
    }

    public function setUserId(string $userId): void
    {
        $this->userId = (int) $userId;
    }

    public function setClientId(string $clientId): void
    {
        $this->clientId = $clientId;
    }

    public function setScopesFromString(?string $scope): void
    {
        $this->scopes = $scope;
    }

    public function setExpires(string $expires): void
    {
        $this->expires = $expires;
    }

    public function setRevoked(bool $revoked): void
    {
        $this->revoked = $revoked;
    }

    public function setDateCreate(string $date): void
    {
        $this->dateCreate = $date;
    }

    public static function queryByToken(string $token): ?static
    {
        return static::query()->where(['token' => $token])->one();
    }
}
