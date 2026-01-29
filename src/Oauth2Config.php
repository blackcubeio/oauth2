<?php

declare(strict_types=1);

/**
 * Oauth2Config.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2;

use InvalidArgumentException;

/**
 * Global OAuth2 configuration holder.
 */
final readonly class Oauth2Config
{
    private const DEFAULT_ALGORITHM = 'RS256';
    private const DEFAULT_ACCESS_TOKEN_TTL = 3600;
    private const DEFAULT_REFRESH_TOKEN_TTL = 2592000;
    private const DEFAULT_ALLOWED_GRANTS = [
        'password',
        'client_credentials',
        'authorization_code',
        'refresh_token',
    ];

    public function __construct(
        private array $config
    ) {
    }

    public function getBaseAlgorithm(): string
    {
        return $this->config['algorithm'] ?? self::DEFAULT_ALGORITHM;
    }

    public function getBaseAccessTokenTtl(): int
    {
        return $this->config['accessTokenTtl'] ?? self::DEFAULT_ACCESS_TOKEN_TTL;
    }

    public function getBaseRefreshTokenTtl(): int
    {
        return $this->config['refreshTokenTtl'] ?? self::DEFAULT_REFRESH_TOKEN_TTL;
    }

    /**
     * @return string[]
     */
    public function getBaseAllowedGrants(): array
    {
        return $this->config['allowedGrants'] ?? self::DEFAULT_ALLOWED_GRANTS;
    }

    /**
     * @return string[]
     */
    public function getPopulations(): array
    {
        return array_keys($this->config['populations'] ?? []);
    }

    public function getPopulationConfig(string $population): PopulationConfig
    {
        $populationConfig = $this->config['populations'][$population]
            ?? throw new InvalidArgumentException("Unknown population: {$population}");

        return new PopulationConfig(
            name: $population,
            config: $populationConfig,
            baseConfig: $this->config
        );
    }
}
