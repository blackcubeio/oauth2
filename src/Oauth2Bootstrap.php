<?php

declare(strict_types=1);

/**
 * Oauth2Bootstrap.php
 *
 * PHP Version 8.3+
 *
 * @copyright 2010-2026 Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2;

use Blackcube\Oauth2\Actions\AuthorizeAction;
use Blackcube\Oauth2\Actions\RevokeAction;
use Blackcube\Oauth2\Actions\TokenAction;
use Yiisoft\Router\Route;
use Yiisoft\Router\RouteCollectorInterface;

final class Oauth2Bootstrap
{
    public function __construct(
        private Oauth2Config $config,
        private RouteCollectorInterface $routeCollector
    ) {
    }

    public function bootstrap(): void
    {
        foreach ($this->config->getPopulations() as $populationName) {
            $population = $this->config->getPopulationConfig($populationName);
            $this->registerPopulationRoutes($population);
        }
    }

    private function registerPopulationRoutes(PopulationConfig $population): void
    {
        $routes = $population->getRoutes();

        if (isset($routes['token'])) {
            $this->routeCollector->addRoute(
                Route::methods($routes['token']['methods'], $routes['token']['pattern'])
                    ->action([TokenAction::class, 'process'])
                    ->name("blauth2.{$population->name}.token")
            );
        }

        if (isset($routes['authorize'])) {
            $this->routeCollector->addRoute(
                Route::methods($routes['authorize']['methods'], $routes['authorize']['pattern'])
                    ->action([AuthorizeAction::class, 'process'])
                    ->name("blauth2.{$population->name}.authorize")
            );
        }

        if (isset($routes['revoke'])) {
            $this->routeCollector->addRoute(
                Route::methods($routes['revoke']['methods'], $routes['revoke']['pattern'])
                    ->action([RevokeAction::class, 'process'])
                    ->name("blauth2.{$population->name}.revoke")
            );
        }
    }
}
