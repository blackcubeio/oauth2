<?php

declare(strict_types=1);

/**
 * JwtValidatorMiddleware.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2\Middleware;

use Blackcube\Oauth2\Interfaces\CypherKeyInterface;
use InvalidArgumentException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Throwable;

final class JwtValidatorMiddleware implements MiddlewareInterface
{
    private const SIGNERS = [
        'RS256' => Signer\Rsa\Sha256::class,
        'RS384' => Signer\Rsa\Sha384::class,
        'RS512' => Signer\Rsa\Sha512::class,
        'HS256' => Signer\Hmac\Sha256::class,
        'HS384' => Signer\Hmac\Sha384::class,
        'HS512' => Signer\Hmac\Sha512::class,
    ];

    /**
     * @param class-string<CypherKeyInterface> $cypherKeyClass
     */
    public function __construct(
        string $cypherKeyClass,
        private ClockInterface $clock,
        private ResponseFactoryInterface $responseFactory,
        private StreamFactoryInterface $streamFactory
    ) {
        $this->cypherKeyClass = $cypherKeyClass;
    }

    /** @var class-string<CypherKeyInterface> */
    private string $cypherKeyClass;

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {
        $token = $this->extractToken($request);

        if ($token === null) {
            return $this->unauthorized('Missing token');
        }

        $claims = $this->validateAndDecode($token);

        if ($claims === null) {
            return $this->unauthorized('Invalid token');
        }

        $request = $request->withAttribute('jwt', $claims);
        $request = $request->withAttribute('userId', $claims['sub']);
        $request = $request->withAttribute('population', $claims['iss']);
        $request = $request->withAttribute('scopes', $claims['scopes']);

        return $handler->handle($request);
    }

    private function extractToken(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine('Authorization');

        if (preg_match('/^Bearer\s+(.+)$/i', $header, $matches)) {
            return $matches[1];
        }

        return null;
    }

    /**
     * @return array{sub: string, iss: string, aud: string, scopes: string[], exp: \DateTimeImmutable, iat: \DateTimeImmutable}|null
     */
    private function validateAndDecode(string $token): ?array
    {
        try {
            // Parse without validation to extract iss
            $parser = new Parser(new JoseEncoder());
            $parsed = $parser->parse($token);

            $issuer = $parsed->claims()->get('iss');
            if ($issuer === null) {
                return null;
            }
            $cypherKey = $this->cypherKeyClass::queryById($issuer);

            if ($cypherKey === null) {
                return null;
            }

            // Reconfigure with the correct key and algorithm
            $config = $this->buildConfiguration($cypherKey);
            $parsed = $config->parser()->parse($token);

            // Validation
            $constraints = [
                new SignedWith($config->signer(), $config->verificationKey()),
                new LooseValidAt($this->clock),
            ];

            if (!$config->validator()->validate($parsed, ...$constraints)) {
                return null;
            }

            $aud = $parsed->claims()->get('aud');
            $audience = is_array($aud) ? ($aud[0] ?? '') : (string) $aud;

            return [
                'sub' => $parsed->claims()->get('sub'),
                'iss' => $parsed->claims()->get('iss'),
                'aud' => $audience,
                'scopes' => $parsed->claims()->get('scopes', []),
                'exp' => $parsed->claims()->get('exp'),
                'iat' => $parsed->claims()->get('iat'),
            ];
        } catch (Throwable) {
            return null;
        }
    }

    private function buildConfiguration(CypherKeyInterface $cypherKey): Configuration
    {
        $algorithm = $cypherKey->getAlgorithm();
        $signerClass = self::SIGNERS[$algorithm] ?? throw new InvalidArgumentException(
            "Unsupported algorithm: {$algorithm}"
        );
        $signer = new $signerClass();

        if (str_starts_with($algorithm, 'RS')) {
            return Configuration::forAsymmetricSigner(
                $signer,
                InMemory::plainText($cypherKey->getPrivateKey()),
                InMemory::plainText($cypherKey->getPublicKey())
            );
        }

        return Configuration::forSymmetricSigner(
            $signer,
            InMemory::plainText($cypherKey->getPrivateKey())
        );
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
