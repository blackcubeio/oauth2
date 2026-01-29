<?php

declare(strict_types=1);

/**
 * ScopeProviderInterface.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2\Interfaces;

/**
 * OAuth2 scope provider contract.
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
