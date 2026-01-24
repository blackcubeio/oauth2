<?php

declare(strict_types=1);

namespace Blackcube\Oauth2\Tests\Support;

use Blackcube\Oauth2\Interfaces\ScopeProviderInterface;

final class TestScopeProvider implements ScopeProviderInterface
{
    private array $availableScopes = ['read', 'write', 'admin', 'profile'];

    public function getAvailableScopes(): array
    {
        return $this->availableScopes;
    }

    public function scopeExists(string $scope): bool
    {
        return in_array($scope, $this->availableScopes, true);
    }

    public function scopesForClient(string $clientId): array
    {
        return $this->availableScopes;
    }

    public function defaultScopesForClient(string $clientId): array
    {
        return ['read', 'profile'];
    }
}
