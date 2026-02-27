<?php

declare(strict_types=1);

/**
 * TokenAction.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2\Actions;

use Blackcube\Oauth2\Interfaces\ScopeProviderInterface;
use Blackcube\Oauth2\PopulationConfig;
use Blackcube\Oauth2\Server\Oauth2ServerFactory;
use Blackcube\Oauth2\Storage\Oauth2Storage;
use OAuth2\Response as Oauth2Response;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class TokenAction implements RequestHandlerInterface
{
    use Oauth2RequestTrait;

    public function __construct(
        private PopulationConfig $populationConfig,
        private ScopeProviderInterface $scopeProvider,
        private ResponseFactoryInterface $responseFactory,
        private StreamFactoryInterface $streamFactory,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $storage = new Oauth2Storage(
            userClass: $this->populationConfig->userQueryClass,
            clientClass: $this->populationConfig->clientQueryClass,
            refreshTokenClass: $this->populationConfig->refreshTokenQueryClass,
            scopeProvider: $this->scopeProvider,
            cypherKeyClass: $this->populationConfig->cypherKeyQueryClass,
        );

        $server = Oauth2ServerFactory::create(
            storage: $storage,
            config: $this->populationConfig,
        );

        $oauth2Request = $this->convertRequest($request);
        $oauth2Response = new Oauth2Response();

        $server->handleTokenRequest($oauth2Request, $oauth2Response);

        return $this->convertResponse($oauth2Response);
    }
}
