<?php
/**
 * Copyright 2026 Adobe
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace Magento\Framework\Cache\Test\Unit\Frontend\Adapter;

use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\Cache\Frontend\Adapter\HmacMarshaller;
use Magento\Framework\Config\ConfigOptionsListConstants;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Marshaller\MarshallerInterface;

class HmacMarshallerTest extends TestCase
{
    private MarshallerInterface&MockObject $inner;
    private DeploymentConfig&MockObject $deploymentConfig;

    protected function setUp(): void
    {
        $this->inner = $this->createMock(MarshallerInterface::class);
        $this->deploymentConfig = $this->createMock(DeploymentConfig::class);

        $this->deploymentConfig
            ->method('get')
            ->with(ConfigOptionsListConstants::CONFIG_PATH_CRYPT_KEY)
            ->willReturn('testsecretkey');
    }

    private function makeMarshaller(): HmacMarshaller
    {
        return new HmacMarshaller($this->inner, $this->deploymentConfig);
    }

    public function testMarshallPrefixesEachValueWithHmac(): void
    {
        $this->inner
            ->expects($this->once())
            ->method('marshall')
            ->with(['k' => 'raw'], $this->anything())
            ->willReturn(['k' => 'serialized']);

        $failed = [];
        $result = $this->makeMarshaller()->marshall(['k' => 'raw'], $failed);

        $this->assertArrayHasKey('k', $result);
        // Format: 64-char hex HMAC + ':' + payload
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}:serialized$/', $result['k']);
    }

    public function testUnmarshallVerifiesHmacAndDelegatesToInner(): void
    {
        $marshaller = $this->makeMarshaller();

        $failed = [];
        $this->inner->method('marshall')->willReturn(['k' => 'inner_payload']);
        $this->inner->method('unmarshall')->with('inner_payload')->willReturn('original_value');

        $tagged = $marshaller->marshall(['k' => 'x'], $failed)['k'];
        $result = $marshaller->unmarshall($tagged);

        $this->assertSame('original_value', $result);
    }

    public function testUnmarshallThrowsOnTamperedPayload(): void
    {
        $marshaller = $this->makeMarshaller();

        $failed = [];
        $this->inner->method('marshall')->willReturn(['k' => 'payload']);
        $tagged = $marshaller->marshall(['k' => 'x'], $failed)['k'];

        // Flip last byte of payload
        $tampered = substr($tagged, 0, -1) . (substr($tagged, -1) === 'x' ? 'y' : 'x');

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/HMAC verification failed/');
        $marshaller->unmarshall($tampered);
    }

    public function testUnmarshallThrowsOnTruncatedEntry(): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/malformed/');
        $this->makeMarshaller()->unmarshall('tooshort');
    }

    public function testUnmarshallThrowsWhenSeparatorMissing(): void
    {
        // 64 hex chars but no colon separator
        $noSep = str_repeat('a', 64) . 'nocolon';

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/malformed/');
        $this->makeMarshaller()->unmarshall($noSep);
    }

    public function testDifferentCryptKeyProducesIncompatibleEntries(): void
    {
        // Marshall with key A
        $this->inner->method('marshall')->willReturn(['k' => 'payload']);
        $failed = [];
        $tagged = $this->makeMarshaller()->marshall(['k' => 'x'], $failed)['k'];

        // Unmarshall with key B → HMAC mismatch
        $otherConfig = $this->createMock(DeploymentConfig::class);
        $otherConfig->method('get')
            ->with(ConfigOptionsListConstants::CONFIG_PATH_CRYPT_KEY)
            ->willReturn('differentkey');
        $otherMarshaller = new HmacMarshaller($this->inner, $otherConfig);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/HMAC verification failed/');
        $otherMarshaller->unmarshall($tagged);
    }

    public function testFailedKeysArePassedThroughFromInnerMarshaller(): void
    {
        $this->inner
            ->method('marshall')
            ->willReturnCallback(function (array $values, ?array &$failed) {
                $failed[] = 'bad_key';
                return ['good_key' => 'serialized'];
            });

        $failed = [];
        $result = $this->makeMarshaller()->marshall(['good_key' => 'a', 'bad_key' => 'b'], $failed);

        $this->assertArrayHasKey('good_key', $result);
        $this->assertContains('bad_key', $failed);
    }

    public function testFreshInstallWithNoCryptKeyDoesNotThrow(): void
    {
        $emptyConfig = $this->createMock(DeploymentConfig::class);
        $emptyConfig->method('get')
            ->with(ConfigOptionsListConstants::CONFIG_PATH_CRYPT_KEY)
            ->willReturn('');

        $this->inner->method('marshall')->willReturn(['k' => 'payload']);
        $this->inner->method('unmarshall')->willReturn('value');

        $marshaller = new HmacMarshaller($this->inner, $emptyConfig);
        $failed = [];
        $tagged = $marshaller->marshall(['k' => 'x'], $failed)['k'];
        $result = $marshaller->unmarshall($tagged);

        $this->assertSame('value', $result);
    }
}
