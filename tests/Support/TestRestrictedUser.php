<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Tests\Support;

/**
 * Test user whose query restricts the scopes, as an application would.
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class TestRestrictedUser extends TestUser
{
    public static function queryByIdentifier(string $identifier): ?static
    {
        $user = parent::queryByIdentifier($identifier);
        if ($user !== null) {
            $user->setRestrictedScopes([
                'read',
                'profile',
            ]);
        }
        return $user;
    }
}
