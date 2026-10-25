<?php

declare(strict_types=1);

/**
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Oauth2\Jwt;

use Blackcube\Oauth2\Interfaces\CypherKeyInterface;
use RuntimeException;

/**
 * Signing key of a population, asymmetric or symmetric.
 *
 * With an `RS*` algorithm, `$rsPublicKey` and `$rsPrivateKey` hold the paths of
 * the files, not their content: a key is only read when it is asked for -
 * signing or verifying a token - and built there when it does not exist yet.
 *
 * With an `HS*` one, `$hsKey` holds the shared secret itself, which the
 * application provides: there is nothing to build, and nothing on disk.
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class CypherKey implements CypherKeyInterface
{
    private const KEY_BITS = 4096;

    private static ?CypherKey $instance = null;

    public function __construct(
        private string $id,
        private string $rsPublicKey = '',
        private string $rsPrivateKey = '',
        private string $hsKey = '',
        private string $algorithm = 'RS256',
        private ?string $temporaryPath = null,
    ) {
        self::$instance = $this;
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getPublicKey(): string
    {
        if ($this->isSymmetric() === true) {
            $key = $this->symmetricKey();
        } else {
            $this->ensureKeyPair();
            $key = (string) file_get_contents($this->rsPublicKey);
        }

        return $key;
    }

    public function getPrivateKey(): string
    {
        if ($this->isSymmetric() === true) {
            $key = $this->symmetricKey();
        } else {
            $this->ensureKeyPair();
            $key = (string) file_get_contents($this->rsPrivateKey);
        }

        return $key;
    }

    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    protected function isSymmetric(): bool
    {
        return str_starts_with($this->algorithm, 'HS');
    }

    /**
     * One secret signs and verifies, so the public side hands out the very same
     * string: Storage\Oauth2Storage::getPublicKey() is called whatever the
     * algorithm, and bshaffer feeds it to the decoder along with it.
     */
    protected function symmetricKey(): string
    {
        if ($this->hsKey === '') {
            throw new RuntimeException(
                'Algorithm ' . $this->algorithm . ' needs hsKey to be configured.'
            );
        }

        return $this->hsKey;
    }

    /**
     * A fresh installation has no keys: they are built on first use and dropped
     * where they are expected, so the next ones find them there.
     *
     * Both are rebuilt together as soon as one is missing: an orphan public key
     * glued back to a new private one would sign tokens nobody could verify.
     */
    protected function ensureKeyPair(): void
    {
        if (is_file($this->rsPublicKey) === false || is_file($this->rsPrivateKey) === false) {
            if (str_starts_with($this->algorithm, 'RS') === false) {
                throw new RuntimeException(
                    'Keys are missing and algorithm ' . $this->algorithm
                    . ' is not supported by the generation: drop them manually.'
                );
            }
            $resource = openssl_pkey_new([
                'private_key_bits' => self::KEY_BITS,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);
            if ($resource === false) {
                throw new RuntimeException('Unable to generate the key pair.');
            }
            $privateKeyPem = '';
            openssl_pkey_export($resource, $privateKeyPem);
            $details = openssl_pkey_get_details($resource);
            if ($details === false) {
                throw new RuntimeException('Unable to read the public key.');
            }
            $this->writeKey($this->rsPrivateKey, $privateKeyPem, 0600);
            $this->writeKey($this->rsPublicKey, (string) $details['key'], 0644);
        }
    }

    /**
     * Two-step write, the intermediate one in the temporary directory: the final
     * file shows up in one go, which keeps a concurrent request from reading a
     * half written key, and no leftover sits next to the keys.
     *
     * A temporary directory sitting on another filesystem costs that guarantee:
     * the kernel cannot move a file across filesystems, so PHP falls back to a
     * copy and the key stops showing up in one go. `temporaryPath` is there to
     * put the temporary file next to the keys when that matters.
     */
    protected function writeKey(string $path, string $content, int $mode): void
    {
        $directory = dirname($path);
        if (is_dir($directory) === false) {
            mkdir($directory, 0700, true);
        }
        $temporaryPath = $this->temporaryPath ?? sys_get_temp_dir();
        $temporaryFile = $temporaryPath . DIRECTORY_SEPARATOR . basename($path) . '.' . bin2hex(random_bytes(6));
        file_put_contents($temporaryFile, $content);
        chmod($temporaryFile, $mode);
        if (rename($temporaryFile, $path) === false) {
            unlink($temporaryFile);
            throw new RuntimeException(sprintf(
                'Unable to move "%s" to "%s".',
                $temporaryFile,
                $path
            ));
        }
    }

    public static function queryById(string $id): ?static
    {
        $found = null;
        if (self::$instance !== null && self::$instance->getId() === $id) {
            $found = self::$instance;
        }
        return $found;
    }

    public static function queryDefault(): ?static
    {
        return self::$instance;
    }
}
