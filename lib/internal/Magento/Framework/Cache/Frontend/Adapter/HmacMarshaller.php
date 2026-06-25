<?php
/**
 * Copyright 2026 Adobe
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace Magento\Framework\Cache\Frontend\Adapter;

use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\Config\ConfigOptionsListConstants;
use Symfony\Component\Cache\Marshaller\MarshallerInterface;

/**
 * HMAC-authenticated marshaller wrapper.
 *
 * Prefixes every serialized cache entry with a keyed HMAC-SHA256 tag derived
 * from the deployment crypt key.  On read, the tag is verified with
 * hash_equals() before any deserialization occurs, preventing object-injection
 * attacks from a compromised cache backend (Redis, filesystem, Memcached).
 *
 * Wire format:  [64-char lowercase hex HMAC][':'][inner-marshalled payload]
 */
class HmacMarshaller implements MarshallerInterface
{
    private const ALGO = 'sha256';
    private const HMAC_HEX_LEN = 64; // SHA-256 → 32 bytes → 64 hex chars
    private const SEPARATOR = ':';

    private string $hmacKey;

    /**
     * @param MarshallerInterface $inner  Inner (de)serializer (e.g. DefaultMarshaller)
     * @param DeploymentConfig $deploymentConfig  Used to derive the HMAC key
     */
    public function __construct(
        private readonly MarshallerInterface $inner,
        DeploymentConfig $deploymentConfig
    ) {
        $rawKey = (string)$deploymentConfig->get(ConfigOptionsListConstants::CONFIG_PATH_CRYPT_KEY);

        if ($rawKey !== '') {
            // Multiple keys are newline-separated; always sign with the latest one.
            $keys = preg_split('/\s+/s', trim($rawKey));
            $activeKey = (string)end($keys);
        } else {
            // No crypt key yet (fresh install): use a per-process random key so
            // cache entries are never shared across restarts — safe, just cold.
            $activeKey = bin2hex(random_bytes(16));
        }

        // Derive a dedicated sub-key so the HMAC key is independent of the
        // encryption key even though both come from the same source material.
        $this->hmacKey = hash(self::ALGO, $activeKey . ':cache-integrity', true);
    }

    /**
     * @inheritdoc
     */
    public function marshall(array $values, ?array &$failed): array
    {
        $serialized = $this->inner->marshall($values, $failed);

        $result = [];
        foreach ($serialized as $key => $payload) {
            $hmac = hash_hmac(self::ALGO, $payload, $this->hmacKey);
            $result[$key] = $hmac . self::SEPARATOR . $payload;
        }

        return $result;
    }

    /**
     * @inheritdoc
     * @throws \UnexpectedValueException If the HMAC is missing, malformed, or does not match.
     */
    public function unmarshall(string $value): mixed
    {
        $minLen = self::HMAC_HEX_LEN + 1; // hmac + separator
        if (strlen($value) < $minLen || $value[self::HMAC_HEX_LEN] !== self::SEPARATOR) {
            throw new \UnexpectedValueException(
                'Cache entry is malformed or was not written by HmacMarshaller.'
            );
        }

        $hmac    = substr($value, 0, self::HMAC_HEX_LEN);
        $payload = substr($value, self::HMAC_HEX_LEN + 1);

        $expected = hash_hmac(self::ALGO, $payload, $this->hmacKey);
        if (!hash_equals($expected, $hmac)) {
            throw new \UnexpectedValueException(
                'Cache HMAC verification failed: entry may have been tampered with.'
            );
        }

        return $this->inner->unmarshall($payload);
    }
}
