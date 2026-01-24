<?php

declare(strict_types=1);

namespace Blackcube\Oauth2\Tests\Support;

use Blackcube\Oauth2\Interfaces\ClientInterface;
use Yiisoft\ActiveRecord\ActiveRecord;

/**
 * @property string $id
 * @property string|null $secret
 * @property string|null $redirectUris
 * @property string|null $allowedGrants
 * @property string $dateCreate
 */
final class TestClient extends ActiveRecord implements ClientInterface
{
    protected string $id = '';
    protected ?string $secret = null;
    protected array|string|null $redirectUris = null;
    protected array|string|null $allowedGrants = null;
    protected \DateTimeImmutable|string $dateCreate = '';

    public function tableName(): string
    {
        return '{{%testClients}}';
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getSecret(): ?string
    {
        return $this->secret;
    }

    public function isPublic(): bool
    {
        return $this->secret === null;
    }

    public function getRedirectUris(): array
    {
        if (is_array($this->redirectUris)) {
            return $this->redirectUris;
        }
        return json_decode($this->redirectUris ?? '[]', true);
    }

    public function getAllowedGrants(): array
    {
        if (is_array($this->allowedGrants)) {
            return $this->allowedGrants;
        }
        return json_decode($this->allowedGrants ?? '["password","refresh_token"]', true);
    }

    public function validateSecret(string $secret): bool
    {
        if ($this->isPublic()) {
            return true;
        }

        return $this->secret === $secret;
    }

    public function setId(string $id): void
    {
        $this->id = $id;
    }

    public function setSecret(?string $secret): void
    {
        $this->secret = $secret;
    }

    public function setRedirectUris(array $uris): void
    {
        $this->redirectUris = json_encode($uris);
    }

    public function setAllowedGrants(array $grants): void
    {
        $this->allowedGrants = json_encode($grants);
    }

    public function setDateCreate(string $date): void
    {
        $this->dateCreate = $date;
    }

    public static function queryById(string $clientId): ?static
    {
        return static::query()->where(['id' => $clientId])->one();
    }
}
