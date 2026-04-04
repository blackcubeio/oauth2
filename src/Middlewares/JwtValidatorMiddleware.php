<?php

declare(strict_types=1);

/**
 * JwtValidatorMiddleware.php
 *
 * PHP Version 8.1
 *
 * @author Philippe Gaultier <philippe@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2\Middlewares;

use Blackcube\Oauth2\Interfaces\CypherKeyInterface;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Stateless JWT validator — multi-issuer, Bearer header, 401 JSON response.
 */
final class JwtValidatorMiddleware extends AbstractJwtMiddleware
{
    /** @var class-string<CypherKeyInterface> */
    private string $cypherKeyClass;

    /**
     * @param class-string<CypherKeyInterface> $cypherKeyClass
     */
    public function __construct(
        string $cypherKeyClass,
        ClockInterface $clock,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {
        parent::__construct($clock);
        $this->cypherKeyClass = $cypherKeyClass;
    }

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {
        $token = $this->extractBearerToken($request);

        if ($token === null) {
            return $this->unauthorized('Missing token');
        }

        // Parse without validation to extract issuer
        $preClaims = $this->parseTokenClaims($token);
        if ($preClaims === null || $preClaims['iss'] === null) {
            return $this->unauthorized('Invalid token');
        }

        // Resolve CypherKey by issuer
        $cypherKey = $this->cypherKeyClass::queryById($preClaims['iss']);
        if ($cypherKey === null) {
            return $this->unauthorized('Invalid token');
        }

        // Full validation
        $claims = $this->validateToken($token, $cypherKey);
        if ($claims === null) {
            return $this->unauthorized('Invalid token');
        }

        $request = $request->withAttribute('jwt', $claims);
        $request = $request->withAttribute('userId', $claims['sub']);
        $request = $request->withAttribute('population', $claims['iss']);
        $request = $request->withAttribute('scopes', $claims['scopes']);

        return $handler->handle($request);
    }

    private function unauthorized(string $message): ResponseInterface
    {
        $response = $this->responseFactory->createResponse(401);
        $response = $response->withHeader('Content-Type', 'application/json');
        $response = $response->withHeader('WWW-Authenticate', 'Bearer');

        $body = json_encode([
            'error' => 'unauthorized',
            'error_description' => $message,
        ], JSON_THROW_ON_ERROR);

        $stream = $this->streamFactory->createStream($body);

        return $response->withBody($stream);
    }
}
