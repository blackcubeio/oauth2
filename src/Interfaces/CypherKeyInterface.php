<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Interfaces;

/**
 * JWT signing key contract.
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
interface CypherKeyInterface
{
    public function getId(): string;
    public function getPublicKey(): string;
    public function getPrivateKey(): string;
    public function getAlgorithm(): string;

    public static function queryById(string $id): ?static;
    public static function queryDefault(): ?static;
}
