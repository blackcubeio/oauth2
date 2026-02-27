<?php

declare(strict_types=1);

/**
 * di.php
 *
 * PHP Version 8.3+
 *
 * @copyright 2010-2026 Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

use Blackcube\Oauth2\Jwt\JwtService;
use Blackcube\Oauth2\PopulationConfig;

/** @var array $params */

return [
    PopulationConfig::class => [
        'class' => PopulationConfig::class,
        '__construct()' => [
            'name' => $params['blackcube/oauth2']['name'],
            'issuer' => $params['blackcube/oauth2']['issuer'],
            'audience' => $params['blackcube/oauth2']['audience'],
            'userQueryClass' => $params['blackcube/oauth2']['userQueryClass'],
            'clientQueryClass' => $params['blackcube/oauth2']['clientQueryClass'],
            'refreshTokenQueryClass' => $params['blackcube/oauth2']['refreshTokenQueryClass'],
            'cypherKeyQueryClass' => $params['blackcube/oauth2']['cypherKeyQueryClass'],
            'algorithm' => $params['blackcube/oauth2']['algorithm'],
            'accessTokenTtl' => $params['blackcube/oauth2']['accessTokenTtl'],
            'refreshTokenTtl' => $params['blackcube/oauth2']['refreshTokenTtl'],
            'allowedGrants' => $params['blackcube/oauth2']['allowedGrants'],
        ],
    ],

    JwtService::class => JwtService::class,
];
