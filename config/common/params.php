<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

return [
    'blackcube/oauth2' => [
        'name' => 'default',
        'issuer' => '',
        'audience' => '',
        'userQueryClass' => '',
        'clientQueryClass' => '',
        'refreshTokenQueryClass' => '',
        'cypherKeyQueryClass' => '',
        'algorithm' => 'RS256',
        'rsPublicKey' => '',
        'rsPrivateKey' => '',
        'hsKey' => '',
        'temporaryPath' => null,
        'accessTokenTtl' => 3600,
        'refreshTokenTtl' => 2592000,
        'allowedGrants' => [
            'password',
            'refresh_token',
        ],
    ],
];
