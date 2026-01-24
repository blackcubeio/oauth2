<?php

declare(strict_types=1);

/**
 * JwtClaims.php
 *
 * PHP Version 8.3+
 *
 * @copyright 2010-2026 Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
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
