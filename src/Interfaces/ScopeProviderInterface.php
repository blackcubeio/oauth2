<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Interfaces;

/**
 * OAuth2 scope provider contract.
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
interface ScopeProviderInterface
{
    /**
     * @return string[]
     */
    public function getAvailableScopes(): array;

    public function scopeExists(string $scope): bool;

    /**
     * @return string[]
     */
    public function scopesForClient(string $clientId): array;

    /**
     * @return string[]
     */
    public function defaultScopesForClient(string $clientId): array;
}
