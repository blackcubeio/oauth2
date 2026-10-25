<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Handlers;

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

/**
 * Token endpoint: issues JWT access tokens and refresh tokens for the grants the population allows.
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class TokenAction implements RequestHandlerInterface
{
    use Oauth2RequestTrait;

    public function __construct(
        private readonly PopulationConfig $populationConfig,
        private readonly ScopeProviderInterface $scopeProvider,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
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
