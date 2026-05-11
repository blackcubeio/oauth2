<?php

declare(strict_types=1);

/**
 * AbstractJwtMiddleware.php
 *
 * PHP Version 8.1
 *
 * @author Philippe Gaultier <philippe@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2\Middlewares;

use Blackcube\Oauth2\Interfaces\CypherKeyInterface;
use InvalidArgumentException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Throwable;

/**
 * Base JWT middleware — shared parse, validate, and configuration logic.
 */
abstract class AbstractJwtMiddleware implements MiddlewareInterface
{
    protected const SIGNERS = [
        'RS256' => Signer\Rsa\Sha256::class,
        'RS384' => Signer\Rsa\Sha384::class,
        'RS512' => Signer\Rsa\Sha512::class,
        'HS256' => Signer\Hmac\Sha256::class,
        'HS384' => Signer\Hmac\Sha384::class,
        'HS512' => Signer\Hmac\Sha512::class,
    ];

    public function __construct(
        protected readonly ClockInterface $clock,
    ) {}

    /**
     * Extract Bearer token from Authorization header.
     */
    protected function extractBearerToken(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine('Authorization');

        if (preg_match('/^Bearer\s+(.+)$/i', $header, $matches)) {
            return $matches[1];
        }

        return null;
    }

    /**
     * Parse a JWT without validation (to extract claims like iss before key resolution).
     *
     * @return array{sub: ?string, iss: ?string, aud: ?string, scopes: string[], exp: ?\DateTimeImmutable, iat: ?\DateTimeImmutable}|null
     */
    protected function parseTokenClaims(string $token): ?array
    {
        try {
            $parser = new Parser(new JoseEncoder());
            $parsed = $parser->parse($token);

            $aud = $parsed->claims()->get('aud');
            $audience = is_array($aud) ? ($aud[0] ?? '') : (string) ($aud ?? '');

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

    /**
     * Parse and validate a JWT against a specific CypherKey.
     *
     * @return array{sub: string, iss: string, aud: string, scopes: string[], exp: ?\DateTimeImmutable, iat: ?\DateTimeImmutable}|null
     */
    protected function validateToken(string $token, CypherKeyInterface $cypherKey): ?array
    {
        try {
            $config = $this->buildJwtConfiguration($cypherKey);
            $parsed = $config->parser()->parse($token);

            $constraints = [
                new SignedWith($config->signer(), $config->verificationKey()),
                new LooseValidAt($this->clock),
            ];

            if (!$config->validator()->validate($parsed, ...$constraints)) {
                return null;
            }

            $aud = $parsed->claims()->get('aud');
            $audience = is_array($aud) ? ($aud[0] ?? '') : (string) ($aud ?? '');

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

    /**
     * Build JWT configuration from a CypherKey.
     */
    protected function buildJwtConfiguration(CypherKeyInterface $cypherKey): Configuration
    {
        $algorithm = $cypherKey->getAlgorithm();
        $signerClass = static::SIGNERS[$algorithm] ?? throw new InvalidArgumentException(
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
}
