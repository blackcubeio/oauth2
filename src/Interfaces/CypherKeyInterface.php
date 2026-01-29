<?php

declare(strict_types=1);

/**
 * CypherKeyInterface.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@blackcube.io>
 * @copyright 2010-2026 Blackcube
 * @license https://blackcube.io/license
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
