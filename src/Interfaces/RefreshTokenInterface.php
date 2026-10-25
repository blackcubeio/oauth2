<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Interfaces;

use DateTimeImmutable;
use DateTimeInterface;

/**
 * OAuth2 refresh token contract.
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
interface RefreshTokenInterface
{
    public function getToken(): string;
    public function setToken(string $token): void;
    public function getUserId(): string;
    public function setUserId(string $userId): void;
    public function getClientId(): string;
    public function setClientId(string $clientId): void;
    public function getScopes(): array;
    public function setScopesFromString(?string $scope): void;
    public function getExpires(): DateTimeInterface;
    public function setExpires(DateTimeImmutable $expires): void;
    public function isRevoked(): bool;
    public function setRevoked(bool $revoked): void;
    public function save(?array $properties = null): void;
    public function revoke(): void;

    public static function queryByToken(string $token): ?static;
}
