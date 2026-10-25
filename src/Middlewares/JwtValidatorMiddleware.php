<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
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
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class JwtValidatorMiddleware extends AbstractJwtMiddleware
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
            $response = $this->unauthorized('Missing token');
        } else {
            $preClaims = $this->parseTokenClaims($token);
            $cypherKey = null;
            if ($preClaims !== null && $preClaims['iss'] !== null) {
                $cypherKey = $this->cypherKeyClass::queryById($preClaims['iss']);
            }

            $claims = null;
            if ($cypherKey !== null) {
                $claims = $this->validateToken($token, $cypherKey);
            }

            if ($claims === null) {
                $response = $this->unauthorized('Invalid token');
            } else {
                $request = $request->withAttribute('jwt', $claims);
                $request = $request->withAttribute('userId', $claims['sub']);
                $request = $request->withAttribute('population', $claims['iss']);
                $request = $request->withAttribute('scopes', $claims['scopes']);

                $response = $handler->handle($request);
            }
        }

        return $response;
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
