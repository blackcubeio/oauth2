<?php

declare(strict_types=1);

/**
 * Oauth2ServerFactory.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2\Server;

use Blackcube\Oauth2\PopulationConfig;
use Blackcube\Oauth2\Storage\Oauth2Storage;
use OAuth2\GrantType\AuthorizationCode;
use OAuth2\GrantType\ClientCredentials;
use OAuth2\GrantType\RefreshToken;
use OAuth2\GrantType\UserCredentials;
use OAuth2\Server;

final class Oauth2ServerFactory
{
    public static function create(
        Oauth2Storage $storage,
        PopulationConfig $config
    ): Server {
        $server = new Server($storage, [
            'access_lifetime' => $config->getAccessTokenTtl(),
            'refresh_token_lifetime' => $config->getRefreshTokenTtl(),
            'use_jwt_access_tokens' => true,
            'issuer' => $config->getIssuer(),
            'allow_implicit' => false,
            'enforce_state' => true,
            'always_issue_new_refresh_token' => true,
        ]);

        $allowedGrants = $config->getAllowedGrants();

        if (in_array('password', $allowedGrants, true)) {
            $server->addGrantType(new UserCredentials($storage));
        }

        if (in_array('client_credentials', $allowedGrants, true)) {
            $server->addGrantType(new ClientCredentials($storage));
        }

        if (in_array('authorization_code', $allowedGrants, true)) {
            $server->addGrantType(new AuthorizationCode($storage));
        }

        if (in_array('refresh_token', $allowedGrants, true)) {
            $server->addGrantType(new RefreshToken($storage, [
                'always_issue_new_refresh_token' => true,
                'unset_refresh_token_after_use' => true,
            ]));
        }

        return $server;
    }
}
