<?php

declare(strict_types=1);

/**
 * RefreshTokenInterface.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2\Interfaces;

use DateTimeInterface;

/**
 * OAuth2 refresh token contract.
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
    public function setExpires(string $expires): void;
    public function isRevoked(): bool;
    public function setRevoked(bool $revoked): void;
    public function save(?array $properties = null): void;
    public function revoke(): void;

    public static function queryByToken(string $token): ?static;
}
