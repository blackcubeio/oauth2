<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\ResponseType;

use OAuth2\Encryption\EncryptionInterface;
use OAuth2\ResponseType\JwtAccessToken as BaseJwtAccessToken;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\Storage\RefreshTokenInterface;

/**
 * JWT access token of a population. bshaffer sets the audience to the client
 * id; a token of a population is meant for the resource of that population, so
 * the audience is the population's, and the client goes in its own claim. The
 * granted scopes are also carried as the scopes array JwtService and the JWT
 * middlewares read back.
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class JwtAccessToken extends BaseJwtAccessToken
{
    public function __construct(
        private readonly string $audience,
        ?PublicKeyInterface $publicKeyStorage = null,
        ?AccessTokenInterface $tokenStorage = null,
        ?RefreshTokenInterface $refreshStorage = null,
        array $config = [],
        ?EncryptionInterface $encryptionUtil = null,
    ) {
        parent::__construct($publicKeyStorage, $tokenStorage, $refreshStorage, $config, $encryptionUtil);
    }

    protected function createPayload($client_id, $user_id, $scope = null)
    {
        $payload = parent::createPayload($client_id, $user_id, $scope);
        $payload['aud'] = $this->audience;
        $payload['client_id'] = $client_id;
        $scopes = [];
        if ($scope !== null && $scope !== '') {
            $scopes = explode(' ', (string) $scope);
        }
        $payload['scopes'] = $scopes;
        return $payload;
    }
}
