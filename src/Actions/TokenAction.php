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

use Blackcube\Oauth2\Interfaces\ClientInterface;
use Blackcube\Oauth2\Interfaces\CypherKeyInterface;
use Blackcube\Oauth2\Interfaces\RefreshTokenInterface;
use Blackcube\Oauth2\Interfaces\ScopeProviderInterface;
use Blackcube\Oauth2\Interfaces\UserInterface;
use Blackcube\Oauth2\PopulationConfig;
use Blackcube\Oauth2\Server\Oauth2ServerFactory;
use Blackcube\Oauth2\Storage\Oauth2Storage;
use OAuth2\Request as Oauth2Request;
use OAuth2\Response as Oauth2Response;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class TokenAction
{
    /**
     * @param class-string<UserInterface> $userClass
     * @param class-string<ClientInterface> $clientClass
     * @param class-string<RefreshTokenInterface> $refreshTokenClass
     * @param class-string<CypherKeyInterface> $cypherKeyClass
     */
    public function __construct(
        private PopulationConfig $populationConfig,
        private string $userClass,
        private string $clientClass,
        private string $refreshTokenClass,
        private ScopeProviderInterface $scopeProvider,
        private string $cypherKeyClass,
        private ResponseFactoryInterface $responseFactory,
        private StreamFactoryInterface $streamFactory
    ) {
    }

    public function process(ServerRequestInterface $request): ResponseInterface
    {
        $storage = new Oauth2Storage(
            userClass: $this->userClass,
            clientClass: $this->clientClass,
            refreshTokenClass: $this->refreshTokenClass,
            scopeProvider: $this->scopeProvider,
            cypherKeyClass: $this->cypherKeyClass
        );

        $server = Oauth2ServerFactory::create(
            storage: $storage,
            config: $this->populationConfig
        );

        $oauth2Request = $this->convertRequest($request);
        $oauth2Response = new Oauth2Response();

        $server->handleTokenRequest($oauth2Request, $oauth2Response);

        return $this->convertResponse($oauth2Response);
    }

    private function convertRequest(ServerRequestInterface $request): Oauth2Request
    {
        $parsedBody = $request->getParsedBody();
        $post = is_array($parsedBody) ? $parsedBody : [];

        return new Oauth2Request(
            query: $request->getQueryParams(),
            request: $post,
            attributes: [],
            cookies: $request->getCookieParams(),
            files: [],
            server: $request->getServerParams(),
            content: null,
            headers: $this->flattenHeaders($request->getHeaders())
        );
    }

    private function convertResponse(Oauth2Response $oauth2Response): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($oauth2Response->getStatusCode());

        foreach ($oauth2Response->getHttpHeaders() as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        $body = $oauth2Response->getResponseBody();
        if ($body !== null && $body !== '') {
            $stream = $this->streamFactory->createStream($body);
            $response = $response->withBody($stream);
        }

        return $response;
    }

    /**
     * @param array<string, string[]> $headers
     * @return array<string, string>
     */
    private function flattenHeaders(array $headers): array
    {
        $flattened = [];
        foreach ($headers as $name => $values) {
            $flattened[$name] = implode(', ', $values);
        }
        return $flattened;
    }
}
