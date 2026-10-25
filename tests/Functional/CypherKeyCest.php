<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Tests\Functional;

use Blackcube\Oauth2\Jwt\CypherKey;
use Blackcube\Oauth2\Tests\Support\FunctionalTester;
use RuntimeException;

/**
 * Generation of the signing keys: the RSA pair built on first use, and the
 * shared secret served as it was configured.
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class CypherKeyCest
{
    private function makeWorkPath(string $name): string
    {
        $path = dirname(__DIR__) . '/_output/cypherKey/' . $name . '-' . bin2hex(random_bytes(4));
        mkdir($path . '/keys', 0700, true);

        return $path;
    }

    public function testKeyPairIsGeneratedOnFirstUse(FunctionalTester $I): void
    {
        $workPath = $this->makeWorkPath('generated');
        $cypherKey = new CypherKey(
            id: 'test-issuer',
            rsPublicKey: $workPath . '/keys/public.pem',
            rsPrivateKey: $workPath . '/keys/private.pem'
        );

        $publicKey = $cypherKey->getPublicKey();
        $privateKey = $cypherKey->getPrivateKey();

        $I->assertFileExists($workPath . '/keys/public.pem');
        $I->assertFileExists($workPath . '/keys/private.pem');
        $I->assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $publicKey);
        $I->assertStringContainsString('PRIVATE KEY', $privateKey);

        $details = openssl_pkey_get_details(openssl_pkey_get_private($privateKey));
        $I->assertEquals($details['key'], $publicKey);
        $I->assertEquals(4096, $details['bits']);
    }

    public function testGeneratedKeysCarryRestrictivePermissions(FunctionalTester $I): void
    {
        $workPath = $this->makeWorkPath('permissions');
        $cypherKey = new CypherKey(
            id: 'test-issuer',
            rsPublicKey: $workPath . '/keys/public.pem',
            rsPrivateKey: $workPath . '/keys/private.pem'
        );

        $cypherKey->getPublicKey();

        $I->assertEquals(0600, fileperms($workPath . '/keys/private.pem') & 0777);
        $I->assertEquals(0644, fileperms($workPath . '/keys/public.pem') & 0777);
    }

    public function testExistingKeysAreLeftUntouched(FunctionalTester $I): void
    {
        $workPath = $this->makeWorkPath('idempotent');
        $cypherKey = new CypherKey(
            id: 'test-issuer',
            rsPublicKey: $workPath . '/keys/public.pem',
            rsPrivateKey: $workPath . '/keys/private.pem'
        );

        $firstPublicKey = $cypherKey->getPublicKey();
        $firstPrivateKey = $cypherKey->getPrivateKey();

        $I->assertEquals($firstPublicKey, $cypherKey->getPublicKey());
        $I->assertEquals($firstPrivateKey, $cypherKey->getPrivateKey());
    }

    public function testBothKeysAreRebuiltWhenOneIsMissing(FunctionalTester $I): void
    {
        $workPath = $this->makeWorkPath('halfMissing');
        $cypherKey = new CypherKey(
            id: 'test-issuer',
            rsPublicKey: $workPath . '/keys/public.pem',
            rsPrivateKey: $workPath . '/keys/private.pem'
        );

        $cypherKey->getPublicKey();
        $firstPrivateKey = $cypherKey->getPrivateKey();
        unlink($workPath . '/keys/public.pem');

        $secondPublicKey = $cypherKey->getPublicKey();
        $secondPrivateKey = $cypherKey->getPrivateKey();

        $I->assertNotEquals($firstPrivateKey, $secondPrivateKey);
        $details = openssl_pkey_get_details(openssl_pkey_get_private($secondPrivateKey));
        $I->assertEquals($details['key'], $secondPublicKey);
    }

    public function testTemporaryPathHoldsNoLeftover(FunctionalTester $I): void
    {
        $workPath = $this->makeWorkPath('temporary');
        mkdir($workPath . '/runtime', 0700, true);
        $cypherKey = new CypherKey(
            id: 'test-issuer',
            rsPublicKey: $workPath . '/keys/public.pem',
            rsPrivateKey: $workPath . '/keys/private.pem',
            temporaryPath: $workPath . '/runtime'
        );

        $cypherKey->getPublicKey();

        $I->assertFileExists($workPath . '/keys/public.pem');
        $I->assertEquals([], glob($workPath . '/runtime/*'));
    }

    public function testSymmetricSecretIsServedOnBothSides(FunctionalTester $I): void
    {
        $workPath = $this->makeWorkPath('symmetric');
        $cypherKey = new CypherKey(
            id: 'test-issuer',
            rsPublicKey: $workPath . '/keys/public.pem',
            rsPrivateKey: $workPath . '/keys/private.pem',
            hsKey: 'a-shared-secret',
            algorithm: 'HS256'
        );

        $I->assertEquals('a-shared-secret', $cypherKey->getPrivateKey());
        $I->assertEquals('a-shared-secret', $cypherKey->getPublicKey());
        $I->assertFileDoesNotExist($workPath . '/keys/public.pem');
        $I->assertFileDoesNotExist($workPath . '/keys/private.pem');
    }

    public function testSymmetricSecretMustBeConfigured(FunctionalTester $I): void
    {
        $cypherKey = new CypherKey(
            id: 'test-issuer',
            algorithm: 'HS256'
        );

        $I->expectThrowable(
            RuntimeException::class,
            static function () use ($cypherKey): void {
                $cypherKey->getPrivateKey();
            }
        );
    }

    public function testUnsupportedAlgorithmIsNotGenerated(FunctionalTester $I): void
    {
        $workPath = $this->makeWorkPath('unsupported');
        $cypherKey = new CypherKey(
            id: 'test-issuer',
            rsPublicKey: $workPath . '/keys/public.pem',
            rsPrivateKey: $workPath . '/keys/private.pem',
            algorithm: 'ES256'
        );

        $I->expectThrowable(
            RuntimeException::class,
            static function () use ($cypherKey): void {
                $cypherKey->getPublicKey();
            }
        );
        $I->assertFileDoesNotExist($workPath . '/keys/public.pem');
    }

    public function testInstanceIsServedByTheStaticContract(FunctionalTester $I): void
    {
        $workPath = $this->makeWorkPath('contract');
        $cypherKey = new CypherKey(
            id: 'test-issuer',
            rsPublicKey: $workPath . '/keys/public.pem',
            rsPrivateKey: $workPath . '/keys/private.pem'
        );

        $I->assertSame($cypherKey, CypherKey::queryDefault());
        $I->assertSame($cypherKey, CypherKey::queryById('test-issuer'));
        $I->assertNull(CypherKey::queryById('another-issuer'));
    }
}
