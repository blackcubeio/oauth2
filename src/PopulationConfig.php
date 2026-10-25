<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
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
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class PopulationConfig
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
     * @param bool $allowImplicit OAuth2 implicit grant flow
     * @param bool $enforceState Force the "state" parameter on authorize requests
     * @param bool $alwaysIssueNewRefreshToken Rotate refresh tokens on every refresh
     */
    public function __construct(
        public readonly string $name,
        public readonly string $issuer,
        public readonly string $audience,
        public readonly string $userQueryClass,
        public readonly string $clientQueryClass,
        public readonly string $refreshTokenQueryClass,
        public readonly string $cypherKeyQueryClass,
        public readonly string $algorithm = 'RS256',
        public readonly int $accessTokenTtl = 3600,
        public readonly int $refreshTokenTtl = 2592000,
        public readonly array $allowedGrants = [
            'password',
            'refresh_token',
        ],
        public readonly bool $allowImplicit = false,
        public readonly bool $enforceState = true,
        public readonly bool $alwaysIssueNewRefreshToken = true,
    ) {
    }
}
