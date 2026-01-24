<?php

declare(strict_types=1);

/**
 * ClientInterface.php
 *
 * PHP Version 8.3+
 *
 * @copyright 2010-2026 Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Interfaces;

/**
 * OAuth2 client contract.
 */
interface ClientInterface
{
    public function getId(): string;
    public function getSecret(): ?string;
    public function isPublic(): bool;
    public function getRedirectUris(): array;
    public function getAllowedGrants(): array;
    public function validateSecret(string $secret): bool;

    public static function queryById(string $clientId): ?static;
}
