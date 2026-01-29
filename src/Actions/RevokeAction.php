<?php

declare(strict_types=1);

/**
 * RevokeAction.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2\Actions;

use Blackcube\Oauth2\Interfaces\RefreshTokenInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class RevokeAction
{
    /**
     * @param class-string<RefreshTokenInterface> $refreshTokenClass
     */
    public function __construct(
        private string $refreshTokenClass,
        private ResponseFactoryInterface $responseFactory,
        private StreamFactoryInterface $streamFactory
    ) {
    }

    public function process(ServerRequestInterface $request): ResponseInterface
    {
        $parsedBody = $request->getParsedBody();
        $params = is_array($parsedBody) ? $parsedBody : [];

        $token = $params['token'] ?? null;
        $tokenTypeHint = $params['token_type_hint'] ?? 'refresh_token';

        if ($token === null) {
            return $this->errorResponse(400, 'invalid_request', 'Missing token parameter');
        }

        // Only refresh tokens can be revoked (v1 scope)
        if ($tokenTypeHint !== 'refresh_token') {
            return $this->errorResponse(400, 'unsupported_token_type', 'Only refresh_token revocation is supported');
        }

        $refreshToken = $this->refreshTokenClass::queryByToken($token);

        if ($refreshToken === null) {
            // RFC 7009: Return 200 even if token doesn't exist
            return $this->successResponse();
        }

        $refreshToken->revoke();

        return $this->successResponse();
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
