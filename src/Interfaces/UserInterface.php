<?php

declare(strict_types=1);

/**
 * UserInterface.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2\Interfaces;

/**
 * OAuth2 resource owner (user) contract.
 */
interface UserInterface
{
    public function getId(): string;
    public function getIdentifier(): string;
    public function getRestrictedScopes(): ?array;
    public function setRestrictedScopes(?array $scopes): void;

    public static function queryById(string $id): ?static;
    public static function queryByIdentifier(string $identifier): ?static;
    public static function queryByIdentifierAndPassword(string $identifier, string $password): ?static;
}
