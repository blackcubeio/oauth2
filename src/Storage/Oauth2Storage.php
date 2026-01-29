<?php

declare(strict_types=1);

/**
 * Oauth2Storage.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2\Storage;

use Blackcube\Oauth2\Interfaces\ClientInterface;
use Blackcube\Oauth2\Interfaces\CypherKeyInterface;
use Blackcube\Oauth2\Interfaces\RefreshTokenInterface;
use Blackcube\Oauth2\Interfaces\ScopeProviderInterface;
use Blackcube\Oauth2\Interfaces\UserInterface;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\Storage\ClientCredentialsInterface;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\Storage\RefreshTokenInterface as Oauth2RefreshTokenInterface;
use OAuth2\Storage\ScopeInterface;
use OAuth2\Storage\UserCredentialsInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class Oauth2Storage implements
    AccessTokenInterface,
    ClientCredentialsInterface,
    Oauth2RefreshTokenInterface,
    UserCredentialsInterface,
    ScopeInterface,
    PublicKeyInterface
{
    /** @var class-string<UserInterface> */
    private string $userClass;
    /** @var class-string<ClientInterface> */
    private string $clientClass;
    /** @var class-string<RefreshTokenInterface> */
    private string $refreshTokenClass;
    /** @var class-string<CypherKeyInterface> */
    private string $cypherKeyClass;
    private LoggerInterface $logger;

    /**
     * @param class-string<UserInterface> $userClass
     * @param class-string<ClientInterface> $clientClass
     * @param class-string<RefreshTokenInterface> $refreshTokenClass
     * @param ScopeProviderInterface $scopeProvider
     * @param class-string<CypherKeyInterface> $cypherKeyClass
     * @param LoggerInterface|null $logger
     */
    public function __construct(
        string $userClass,
        string $clientClass,
        string $refreshTokenClass,
        private ScopeProviderInterface $scopeProvider,
        string $cypherKeyClass,
        ?LoggerInterface $logger = null
    ) {
        $this->userClass = $userClass;
        $this->clientClass = $clientClass;
        $this->refreshTokenClass = $refreshTokenClass;
        $this->cypherKeyClass = $cypherKeyClass;
        $this->logger = $logger ?? new NullLogger();
    }

    // ========== AccessTokenInterface ==========

    public function getAccessToken($oauth_token): ?array
    {
        // JWT tokens are self-contained, no storage lookup needed
        return null;
    }

    public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = null): bool
    {
        // JWT tokens are self-contained, no storage needed
        return true;
    }

    // ========== ClientCredentialsInterface ==========

    public function getClientDetails($client_id): array|false
    {
        $client = $this->clientClass::queryById($client_id);

        if ($client === null) {
            return false;
        }

        return [
            'client_id' => $client->getId(),
            'client_secret' => $client->getSecret(),
            'redirect_uri' => implode(' ', $client->getRedirectUris()),
            'grant_types' => implode(' ', $client->getAllowedGrants()),
        ];
    }

    public function getClientScope($client_id): string
    {
        return implode(' ', $this->scopeProvider->scopesForClient($client_id));
    }

    public function checkRestrictedGrantType($client_id, $grant_type): bool
    {
        $client = $this->clientClass::queryById($client_id);

        if ($client === null) {
            return false;
        }

        return in_array($grant_type, $client->getAllowedGrants(), true);
    }

    public function checkClientCredentials($client_id, $client_secret = null): bool
    {
        $client = $this->clientClass::queryById($client_id);

        if ($client === null) {
            return false;
        }

        if ($client->isPublic()) {
            return true;
        }

        if ($client_secret === null) {
            return false;
        }

        return $client->validateSecret($client_secret);
    }

    public function isPublicClient($client_id): bool
    {
        $client = $this->clientClass::queryById($client_id);

        return $client?->isPublic() ?? false;
    }

    // ========== RefreshTokenInterface ==========

    public function getRefreshToken($refresh_token): ?array
    {
        $this->logger->debug('getRefreshToken called', ['token' => $refresh_token]);

        $token = $this->refreshTokenClass::queryByToken($refresh_token);

        if ($token === null) {
            $this->logger->debug('getRefreshToken: token not found in database');
            return null;
        }

        if ($token->isRevoked()) {
            $this->logger->debug('getRefreshToken: token is revoked');
            return null;
        }

        $this->logger->debug('getRefreshToken: token found', [
            'user_id' => $token->getUserId(),
            'client_id' => $token->getClientId(),
        ]);

        return [
            'refresh_token' => $token->getToken(),
            'client_id' => $token->getClientId(),
            'user_id' => $token->getUserId(),
            'expires' => $token->getExpires()->getTimestamp(),
            'scope' => implode(' ', $token->getScopes()),
        ];
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
        $token->setExpires(date('Y-m-d H:i:s', $expires));
        $token->setScopesFromString($scope);
        $token->setRevoked(false);
        $token->save();

        $this->logger->debug('setRefreshToken saved successfully');

        return true;
    }

    public function unsetRefreshToken($refresh_token): bool
    {
        $token = $this->refreshTokenClass::queryByToken($refresh_token);

        if ($token === null) {
            return false;
        }

        try {
            $token->revoke();
            return true;
        } catch (\Throwable $e) {
            $this->logger->error('Failed to revoke refresh token', [
                'token' => $refresh_token,
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    // ========== UserCredentialsInterface ==========

    public function checkUserCredentials($username, $password): bool
    {
        return $this->userClass::queryByIdentifierAndPassword($username, $password) !== null;
    }

    public function getUserDetails($username): array|false
    {
        $user = $this->userClass::queryByIdentifier($username);

        if ($user === null) {
            return false;
        }

        return [
            'user_id' => $user->getId(),
            'scope' => null,
        ];
    }

    // ========== ScopeInterface ==========

    public function scopeExists($scope): bool
    {
        $scopes = explode(' ', $scope);

        foreach ($scopes as $s) {
            if (!$this->scopeProvider->scopeExists($s)) {
                return false;
            }
        }

        return true;
    }

    public function getDefaultScope($client_id = null): ?string
    {
        if ($client_id === null) {
            return null;
        }

        $scopes = $this->scopeProvider->defaultScopesForClient($client_id);

        return empty($scopes) ? null : implode(' ', $scopes);
    }

    // ========== PublicKeyInterface ==========

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
