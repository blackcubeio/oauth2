<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Interfaces;

/**
 * OAuth2 resource owner (user) contract.
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
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
