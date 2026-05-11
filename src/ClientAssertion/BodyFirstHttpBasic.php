<?php

declare(strict_types=1);

/**
 * BodyFirstHttpBasic.php
 *
 * PHP Version 8.1
 *
 * @author Philippe Gaultier <philippe@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
 */

namespace Blackcube\Oauth2\ClientAssertion;

use OAuth2\ClientAssertionType\HttpBasic;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 * Inverts bshaffer's default precedence: when client credentials are present
 * in the request body, they take priority over an HTTP Basic header. This
 * lets an OAuth2 token endpoint coexist with a server-level Basic Auth gate
 * (RFC 6749 §2.3.1 allows either source without ordering).
 */
final class BodyFirstHttpBasic extends HttpBasic
{
    public function getClientCredentials(RequestInterface $request, ?ResponseInterface $response = null)
    {
        if ($this->config['allow_credentials_in_request_body'] === true
            && $request->request('client_id') !== null
        ) {
            return [
                'client_id' => $request->request('client_id'),
                'client_secret' => $request->request('client_secret'),
            ];
        }
        return parent::getClientCredentials($request, $response);
    }
}
