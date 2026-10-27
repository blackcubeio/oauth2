<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Storage;

use Blackcube\Oauth2\Interfaces\ClientInterface;
use Blackcube\Oauth2\Interfaces\CypherKeyInterface;
use Blackcube\Oauth2\Interfaces\RefreshTokenInterface;
use Blackcube\Oauth2\Interfaces\ScopeProviderInterface;
use Blackcube\Oauth2\Interfaces\UserInterface;
use DateTimeImmutable;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\Storage\ClientCredentialsInterface;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\Storage\RefreshTokenInterface as Oauth2RefreshTokenInterface;
use OAuth2\Storage\ScopeInterface;
use OAuth2\Storage\UserCredentialsInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * OAuth2 server storage backed by the population's user, client, refresh-token and cypher-key classes.
 *
 * Access tokens are stateless JWTs: they are never stored.
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class Oauth2Storage implements
    AccessTokenInterface,
    ClientCredentialsInterface,
    Oauth2RefreshTokenInterface,
    UserCredentialsInterface,
    ScopeInterface,
    PublicKeyInterface
{
    private readonly LoggerInterface $logger;

    /**
     * @param class-string<UserInterface> $userClass
     * @param class-string<ClientInterface> $clientClass
     * @param class-string<RefreshTokenInterface> $refreshTokenClass
     * @param ScopeProviderInterface $scopeProvider
     * @param class-string<CypherKeyInterface> $cypherKeyClass
     * @param LoggerInterface|null $logger
     */
    public function __construct(
        private readonly string $userClass,
        private readonly string $clientClass,
        private readonly string $refreshTokenClass,
        private readonly ScopeProviderInterface $scopeProvider,
        private readonly string $cypherKeyClass,
        ?LoggerInterface $logger = null
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    public function getAccessToken($oauth_token): ?array
    {
        return null;
    }

    public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = null): bool
    {
        return true;
    }

    public function getClientDetails($client_id): array|false
    {
        $details = false;
        $client = $this->clientClass::queryById($client_id);

        if ($client !== null) {
            $details = [
                'client_id' => $client->getId(),
                'client_secret' => $client->getSecret(),
                'redirect_uri' => implode(' ', $client->getRedirectUris()),
                'grant_types' => implode(' ', $client->getAllowedGrants()),
            ];
        }

        return $details;
    }

    public function getClientScope($client_id): string
    {
        return implode(' ', $this->scopeProvider->scopesForClient($client_id));
    }

    public function checkRestrictedGrantType($client_id, $grant_type): bool
    {
        $isAllowed = false;
        $client = $this->clientClass::queryById($client_id);

        if ($client !== null) {
            $isAllowed = in_array($grant_type, $client->getAllowedGrants(), true) === true;
        }

        return $isAllowed;
    }

    public function checkClientCredentials($client_id, $client_secret = null): bool
    {
        $isValid = false;
        $client = $this->clientClass::queryById($client_id);

        if ($client !== null) {
            if ($client->isPublic() === true) {
                $isValid = true;
            } elseif ($client_secret !== null) {
                $isValid = $client->validateSecret($client_secret);
            }
        }

        return $isValid;
    }

    public function isPublicClient($client_id): bool
    {
        $client = $this->clientClass::queryById($client_id);

        return $client?->isPublic() ?? false;
    }

    public function getRefreshToken($refresh_token): ?array
    {
        $this->logger->debug('getRefreshToken called', ['token' => $refresh_token]);

        $tokenData = null;
        $token = $this->refreshTokenClass::queryByToken($refresh_token);

        if ($token === null) {
            $this->logger->debug('getRefreshToken: token not found in database');
        } elseif ($token->isRevoked() === true) {
            $this->logger->debug('getRefreshToken: token is revoked');
        } else {
            $this->logger->debug('getRefreshToken: token found', [
                'user_id' => $token->getUserId(),
                'client_id' => $token->getClientId(),
            ]);

            $tokenData = [
                'refresh_token' => $token->getToken(),
                'client_id' => $token->getClientId(),
                'user_id' => $token->getUserId(),
                'expires' => $token->getExpires()->getTimestamp(),
                'scope' => implode(' ', $token->getScopes()),
            ];
        }

        return $tokenData;
    }

    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null): bool
    {
        $this->logger->debug('setRefreshToken called', [
            'token' => $refresh_token,
            'client_id' => $client_id,
            'user_id' => $user_id,
            'expires' => $expires,
        ]);

        $token = new $this->refreshTokenClass();
        $token->setToken($refresh_token);
        $token->setClientId($client_id);
        $token->setUserId($user_id);
        $token->setExpires((new DateTimeImmutable())->setTimestamp($expires));
        $token->setScopesFromString($scope);
        $token->setRevoked(false);

        $isSaved = false;
        try {
            $token->save();
            $isSaved = true;
        } catch (\Throwable $e) {
            $this->logger->error('setRefreshToken save failed', ['exception' => $e->getMessage()]);
        }

        if ($isSaved === true) {
            $this->logger->debug('setRefreshToken saved successfully');
        }

        return $isSaved;
    }

    public function unsetRefreshToken($refresh_token): bool
    {
        $isRevoked = false;
        $token = $this->refreshTokenClass::queryByToken($refresh_token);

        if ($token !== null) {
            try {
                $token->revoke();
                $isRevoked = true;
            } catch (\Throwable $e) {
                $this->logger->error('Failed to revoke refresh token', [
                    'token' => $refresh_token,
                    'error' => $e->getMessage(),
                ]);
            }
        }

        return $isRevoked;
    }

    public function checkUserCredentials($username, $password): bool
    {
        return $this->userClass::queryByIdentifierAndPassword($username, $password) !== null;
    }

    public function getUserDetails($username): array|false
    {
        $details = false;
        $user = $this->userClass::queryByIdentifier($username);

        if ($user !== null) {
            $restrictedScopes = $user->getRestrictedScopes();
            $scope = null;
            if ($restrictedScopes !== null) {
                $scope = implode(' ', $restrictedScopes);
            }
            $details = [
                'user_id' => $user->getId(),
                'scope' => $scope,
            ];
        }

        return $details;
    }

    public function scopeExists($scope): bool
    {
        $exists = true;
        $scopes = explode(' ', $scope);

        foreach ($scopes as $scopeName) {
            if ($exists === true && $this->scopeProvider->scopeExists($scopeName) === false) {
                $exists = false;
            }
        }

        return $exists;
    }

    public function getDefaultScope($client_id = null): ?string
    {
        $defaultScope = null;
        if ($client_id !== null) {
            $scopes = $this->scopeProvider->defaultScopesForClient($client_id);
            $defaultScope = empty($scopes) === true ? null : implode(' ', $scopes);
        }

        return $defaultScope;
    }

    public function getPublicKey($client_id = null): ?string
    {
        $cypherKey = $this->cypherKeyClass::queryDefault();

        return $cypherKey?->getPublicKey();
    }

    public function getPrivateKey($client_id = null): ?string
    {
        $cypherKey = $this->cypherKeyClass::queryDefault();

        return $cypherKey?->getPrivateKey();
    }

    public function getEncryptionAlgorithm($client_id = null): string
    {
        $cypherKey = $this->cypherKeyClass::queryDefault();

        return $cypherKey?->getAlgorithm() ?? 'RS256';
    }
}
