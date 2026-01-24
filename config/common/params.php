<?php

declare(strict_types=1);

/**
 * params.php
 *
 * PHP Version 8.3+
 *
 * @copyright 2010-2026 Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

return [
    'blackcube/yii-oauth2' => [
        'algorithm' => 'RS256',
        'accessTokenTtl' => 3600,
        'refreshTokenTtl' => 2592000,
        'allowedGrants' => [
            'password',
            'client_credentials',
            'authorization_code',
            'refresh_token',
        ],
        'populations' => [],
    ],
];
