<?php

declare(strict_types=1);

/**
 * PopulationConfig.php
 *
 * PHP Version 8.3+
 *
 * @copyright 2010-2026 Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2;

use InvalidArgumentException;

/**
 * OAuth2 population-specific configuration.
 */
final readonly class PopulationConfig
{
    private const DEFAULT_ALGORITHM = 'RS256';
    private const DEFAULT_ACCESS_TOKEN_TTL = 3600;
    private const DEFAULT_REFRESH_TOKEN_TTL = 2592000;
    private const DEFAULT_ALLOWED_GRANTS = [
        'password',
        'refresh_token',
    ];

    public function __construct(
        public string $name,
        private array $config,
        private array $baseConfig
    ) {
    }

    public function getAlgorithm(): string
    {
        return $this->config['algorithm']
            ?? $this->baseConfig['algorithm']
            ?? self::DEFAULT_ALGORITHM;
    }

    public function getAccessTokenTtl(): int
    {
        return $this->config['accessTokenTtl']
            ?? $this->baseConfig['accessTokenTtl']
            ?? self::DEFAULT_ACCESS_TOKEN_TTL;
    }

    public function getRefreshTokenTtl(): int
    {
        return $this->config['refreshTokenTtl']
            ?? $this->baseConfig['refreshTokenTtl']
            ?? self::DEFAULT_REFRESH_TOKEN_TTL;
    }

    /**
     * @return string[]
     */
    public function getAllowedGrants(): array
    {
        return $this->config['allowedGrants']
            ?? $this->baseConfig['allowedGrants']
            ?? self::DEFAULT_ALLOWED_GRANTS;
    }

    public function getIssuer(): string
    {
        return $this->config['issuer']
            ?? throw new InvalidArgumentException("Missing issuer for population: {$this->name}");
    }

    public function getAudience(): string
    {
        return $this->config['audience']
            ?? throw new InvalidArgumentException("Missing audience for population: {$this->name}");
    }

    public function getUserQueryClass(): string
    {
        return $this->config['userQuery']
            ?? throw new InvalidArgumentException("Missing userQuery for population: {$this->name}");
    }

    public function getClientQueryClass(): string
    {
        return $this->config['clientQuery']
            ?? throw new InvalidArgumentException("Missing clientQuery for population: {$this->name}");
    }

    public function getRefreshTokenQueryClass(): string
    {
        return $this->config['refreshTokenQuery']
            ?? throw new InvalidArgumentException("Missing refreshTokenQuery for population: {$this->name}");
    }

    public function getScopeProviderClass(): string
    {
        return $this->config['scopeProvider']
            ?? throw new InvalidArgumentException("Missing scopeProvider for population: {$this->name}");
    }

    public function getCypherKeyQueryClass(): string
    {
        return $this->config['cypherKeyQuery']
            ?? throw new InvalidArgumentException("Missing cypherKeyQuery for population: {$this->name}");
    }

    /**
     * @return array<string, array{pattern: string, methods: string[]}>
     */
    public function getRoutes(): array
    {
        return $this->config['routes'] ?? [];
    }

    /**
     * @return array{pattern: string, methods: string[]}|null
     */
    public function getRoute(string $name): ?array
    {
        return $this->config['routes'][$name] ?? null;
    }
}
