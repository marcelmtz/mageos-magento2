<?php
/**
 * Copyright 2026 Adobe
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace Magento\Framework\Cache\Frontend\Adapter;

use Symfony\Component\Cache\Marshaller\MarshallerInterface;

/**
 * HMAC-authenticated marshaller wrapper.
 *
 * Prefixes every serialized cache entry with a keyed HMAC-SHA256 tag.
 * On read, the tag is verified with hash_equals() before any deserialization
 * occurs, preventing object-injection attacks from a compromised cache backend
 * (Redis, filesystem, Memcached).
 *
 * Wire format:  [64-char lowercase hex HMAC][':'][inner-marshalled payload]
 *
 * The caller is responsible for supplying a cryptographically strong $hmacKey.
 * In Magento, SymfonyAdapterProvider derives this from the deployment crypt key.
 */
class HmacMarshaller implements MarshallerInterface
{
    private const ALGO = 'sha256';
    private const HMAC_HEX_LEN = 64; // SHA-256 → 32 bytes → 64 hex chars
    private const SEPARATOR = ':';

    /**
     * @param MarshallerInterface $inner  Inner (de)serializer (e.g. DefaultMarshaller)
     * @param string $hmacKey  Raw binary or hex key material for HMAC-SHA256
     */
    public function __construct(
        private readonly MarshallerInterface $inner,
        #[\SensitiveParameter] private readonly string $hmacKey
    ) {
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
