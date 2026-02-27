<?php

declare(strict_types=1);

/**
 * PopulationConfig.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2;

use Blackcube\Oauth2\Interfaces\ClientInterface;
use Blackcube\Oauth2\Interfaces\CypherKeyInterface;
use Blackcube\Oauth2\Interfaces\RefreshTokenInterface;
use Blackcube\Oauth2\Interfaces\UserInterface;

/**
 * OAuth2 population configuration.
 *
 * @template TUser of UserInterface
 * @template TClient of ClientInterface
 * @template TRefreshToken of RefreshTokenInterface
 * @template TCypherKey of CypherKeyInterface
 */
final readonly class PopulationConfig
{
    /**
     * @param string $name Population name
     * @param string $issuer JWT issuer
     * @param string $audience JWT audience
     * @param class-string<TUser> $userQueryClass
     * @param class-string<TClient> $clientQueryClass
     * @param class-string<TRefreshToken> $refreshTokenQueryClass
     * @param class-string<TCypherKey> $cypherKeyQueryClass
     * @param string $algorithm Signing algorithm
     * @param int $accessTokenTtl in seconds
     * @param int $refreshTokenTtl in seconds
     * @param string[] $allowedGrants
     */
    public function __construct(
        public string $name,
        public string $issuer,
        public string $audience,
        public string $userQueryClass,
        public string $clientQueryClass,
        public string $refreshTokenQueryClass,
        public string $cypherKeyQueryClass,
        public string $algorithm = 'RS256',
        public int $accessTokenTtl = 3600,
        public int $refreshTokenTtl = 2592000,
        public array $allowedGrants = ['password', 'refresh_token'],
    ) {
    }
}
