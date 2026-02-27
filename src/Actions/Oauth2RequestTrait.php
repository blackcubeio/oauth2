<?php

declare(strict_types=1);

/**
 * Oauth2RequestTrait.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2\Actions;

use OAuth2\Request as Oauth2Request;
use OAuth2\Response as Oauth2Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

trait Oauth2RequestTrait
{
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
