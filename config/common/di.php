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

use Blackcube\Oauth2\Oauth2Config;
use Blackcube\Oauth2\Jwt\JwtService;
use Yiisoft\Aliases\Aliases;

/** @var array $params */

return [
    Oauth2Config::class => static function (Aliases $aliases) use ($params): Oauth2Config {
        $config = $params['blackcube/yii-oauth2'];

        // Resolve @web alias for route patterns in each population
        foreach ($config['populations'] as $popName => $popConfig) {
            if (isset($popConfig['routes'])) {
                foreach ($popConfig['routes'] as $routeName => $routeConfig) {
                    if (isset($routeConfig['pattern'])) {
                        $config['populations'][$popName]['routes'][$routeName]['pattern'] =
                            $aliases->get($routeConfig['pattern']);
                    }
                }
            }
        }

        return new Oauth2Config($config);
    },

    JwtService::class => JwtService::class,
];
