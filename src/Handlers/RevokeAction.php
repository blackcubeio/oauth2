<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Handlers;

use Blackcube\Oauth2\PopulationConfig;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Revocation endpoint (RFC 7009): revokes a refresh token; an unknown token still answers 200.
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class RevokeAction implements RequestHandlerInterface
{
    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly PopulationConfig $populationConfig,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $parsedBody = $request->getParsedBody();
        $bodyParams = is_array($parsedBody) === true ? $parsedBody : [];

        $token = $bodyParams['token'] ?? null;
        $tokenTypeHint = $bodyParams['token_type_hint'] ?? 'refresh_token';

        if ($token === null) {
            $response = $this->errorResponse(400, 'invalid_request', 'Missing token parameter');
        } elseif ($tokenTypeHint !== 'refresh_token') {
            $response = $this->errorResponse(400, 'unsupported_token_type', 'Only refresh_token revocation is supported');
        } else {
            $refreshTokenClass = $this->populationConfig->refreshTokenQueryClass;
            $refreshToken = $refreshTokenClass::queryByToken($token);

            $response = $this->successResponse();
            if ($refreshToken !== null) {
                try {
                    $refreshToken->revoke();
                } catch (\Throwable $e) {
                    $this->logger->error('Refresh token revocation failed', [
                        'exception' => $e,
                    ]);
                    $response = $this->errorResponse(503, 'temporarily_unavailable', 'Token revocation failed');
                }
            }
        }

        return $response;
    }

    private function successResponse(): ResponseInterface
    {
        return $this->responseFactory->createResponse(200);
    }

    private function errorResponse(int $status, string $error, string $description): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($status);
        $response = $response->withHeader('Content-Type', 'application/json');

        $body = json_encode([
            'error' => $error,
            'error_description' => $description,
        ], JSON_THROW_ON_ERROR);

        $stream = $this->streamFactory->createStream($body);

        return $response->withBody($stream);
    }
}
