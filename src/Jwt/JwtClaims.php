<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Jwt;

use DateTimeImmutable;

/**
 * Claims of a decoded JWT: subject, issuer, audience, scopes, expiry and issue dates.
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class JwtClaims
{
    /**
     * @param string[] $scopes
     */
    public function __construct(
        public readonly string $sub,
        public readonly string $iss,
        public readonly string $aud,
        public readonly array $scopes,
        public readonly DateTimeImmutable $exp,
        public readonly DateTimeImmutable $iat
    ) {
    }

    public function isExpired(): bool
    {
        $now = new DateTimeImmutable();
        return $this->exp < $now;
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true) === true;
    }
}
