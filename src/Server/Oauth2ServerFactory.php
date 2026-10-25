<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Server;

use Blackcube\Oauth2\ClientAssertion\BodyFirstHttpBasic;
use Blackcube\Oauth2\PopulationConfig;
use Blackcube\Oauth2\ResponseType\JwtAccessToken;
use Blackcube\Oauth2\Storage\Oauth2Storage;
use OAuth2\ClientAssertionType\ClientAssertionTypeInterface;
use OAuth2\GrantType\AuthorizationCode;
use OAuth2\GrantType\ClientCredentials;
use OAuth2\GrantType\RefreshToken;
use OAuth2\GrantType\UserCredentials;
use OAuth2\ScopeInterface;
use OAuth2\Server;
use OAuth2\TokenType\TokenTypeInterface;

/**
 * Builds the OAuth2 server of a population: JWT access tokens, body-first client credentials, the grants it allows.
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class Oauth2ServerFactory
{
    /**
     * @param array<int, \OAuth2\GrantType\GrantTypeInterface> $customGrants
     * @param array<string, \OAuth2\ResponseType\ResponseTypeInterface> $customResponseTypes
     */
    public static function create(
        Oauth2Storage $storage,
        PopulationConfig $config,
        array $customGrants = [],
        array $customResponseTypes = [],
        ?TokenTypeInterface $tokenType = null,
        ?ScopeInterface $scopeUtil = null,
        ?ClientAssertionTypeInterface $clientAssertionType = null,
    ): Server {
        $clientAssertionType ??= new BodyFirstHttpBasic($storage, [
            'allow_credentials_in_request_body' => true,
            'allow_public_clients' => true,
        ]);

        $customResponseTypes['token'] ??= new JwtAccessToken($config->audience, $storage, $storage, $storage, [
            'store_encrypted_token_string' => true,
            'issuer' => $config->issuer,
            'access_lifetime' => $config->accessTokenTtl,
            'refresh_token_lifetime' => $config->refreshTokenTtl,
        ]);

        $server = new Server(
            $storage,
            [
                'access_lifetime' => $config->accessTokenTtl,
                'refresh_token_lifetime' => $config->refreshTokenTtl,
                'use_jwt_access_tokens' => true,
                'issuer' => $config->issuer,
                'allow_implicit' => $config->allowImplicit,
                'enforce_state' => $config->enforceState,
                'always_issue_new_refresh_token' => $config->alwaysIssueNewRefreshToken,
            ],
            [],
            $customResponseTypes,
            $tokenType,
            $scopeUtil,
            $clientAssertionType,
        );

        $allowedGrants = $config->allowedGrants;

        if (in_array('password', $allowedGrants, true) === true) {
            $server->addGrantType(new UserCredentials($storage));
        }

        if (in_array('client_credentials', $allowedGrants, true) === true) {
            $server->addGrantType(new ClientCredentials($storage));
        }

        if (in_array('authorization_code', $allowedGrants, true) === true) {
            $server->addGrantType(new AuthorizationCode($storage));
        }

        if (in_array('refresh_token', $allowedGrants, true) === true) {
            $server->addGrantType(new RefreshToken($storage, [
                'always_issue_new_refresh_token' => $config->alwaysIssueNewRefreshToken,
                'unset_refresh_token_after_use' => true,
            ]));
        }

        foreach ($customGrants as $grant) {
            $server->addGrantType($grant);
        }

        return $server;
    }
}
