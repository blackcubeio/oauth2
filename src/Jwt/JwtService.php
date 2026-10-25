<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Jwt;

use Blackcube\Oauth2\Interfaces\CypherKeyInterface;
use DateTimeImmutable;
use InvalidArgumentException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Throwable;

/**
 * Encodes and decodes JWT access tokens signed with a CypherKey (RSA or HMAC).
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class JwtService
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
     * @param string[] $scopes
     */
    public function encode(
        CypherKeyInterface $cypherKey,
        string $subject,
        string $issuer,
        string $audience,
        array $scopes,
        int $ttl
    ): string {
        $config = $this->buildConfiguration($cypherKey);
        $now = new DateTimeImmutable();

        $token = $config->builder()
            ->issuedBy($issuer)
            ->permittedFor($audience)
            ->relatedTo($subject)
            ->issuedAt($now)
            ->expiresAt($now->modify('+' . $ttl . ' seconds'))
            ->withClaim('scopes', $scopes)
            ->getToken($config->signer(), $config->signingKey());

        return $token->toString();
    }

    public function decode(
        string $token,
        CypherKeyInterface $cypherKey
    ): ?JwtClaims {
        $claims = null;
        try {
            $config = $this->buildConfiguration($cypherKey);
            $parsed = $config->parser()->parse($token);

            $signedWithConstraint = new SignedWith($config->signer(), $config->verificationKey());
            if ($config->validator()->validate($parsed, $signedWithConstraint) === true) {
                $aud = $parsed->claims()->get('aud');
                $audience = is_array($aud) === true ? ($aud[0] ?? '') : (string) $aud;

                $claims = new JwtClaims(
                    sub: $parsed->claims()->get('sub'),
                    iss: $parsed->claims()->get('iss'),
                    aud: $audience,
                    scopes: $parsed->claims()->get('scopes', []),
                    exp: $parsed->claims()->get('exp'),
                    iat: $parsed->claims()->get('iat')
                );
            }
        } catch (Throwable) {
            $claims = null;
        }
        return $claims;
    }

    private function buildConfiguration(CypherKeyInterface $cypherKey): Configuration
    {
        $algorithm = $cypherKey->getAlgorithm();
        $signerClass = self::SIGNERS[$algorithm] ?? throw new InvalidArgumentException(
            'Unsupported algorithm: ' . $algorithm
        );
        $signer = new $signerClass();

        if (str_starts_with($algorithm, 'RS') === true) {
            $configuration = Configuration::forAsymmetricSigner(
                $signer,
                InMemory::plainText($cypherKey->getPrivateKey()),
                InMemory::plainText($cypherKey->getPublicKey())
            );
        } else {
            $configuration = Configuration::forSymmetricSigner(
                $signer,
                InMemory::plainText($cypherKey->getPrivateKey())
            );
        }

        return $configuration;
    }
}
