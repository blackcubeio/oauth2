<?php

declare(strict_types=1);

/**
 * JwtClaims.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2\Jwt;

use DateTimeImmutable;

final readonly class JwtClaims
{
    /**
     * @param string[] $scopes
     */
    public function __construct(
        public string $sub,
        public string $iss,
        public string $aud,
        public array $scopes,
        public DateTimeImmutable $exp,
        public DateTimeImmutable $iat
    ) {
    }

    public function isExpired(): bool
    {
        return $this->exp < new DateTimeImmutable();
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}
