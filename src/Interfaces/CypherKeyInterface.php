<?php

declare(strict_types=1);

/**
 * CypherKeyInterface.php
 *
 * PHP Version 8.3+
 *
 * @copyright 2010-2026 Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Interfaces;

/**
 * JWT signing key contract.
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
