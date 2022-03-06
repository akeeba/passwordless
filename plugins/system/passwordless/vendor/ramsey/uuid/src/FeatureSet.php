<?php

/**
 * This file is part of the ramsey/uuid library
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @copyright Copyright (c) Ben Ramsey <ben@benramsey.com>
 * @license http://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace Akeeba\Passwordless\Ramsey\Uuid;

use Akeeba\Passwordless\Ramsey\Uuid\Builder\BuilderCollection;
use Akeeba\Passwordless\Ramsey\Uuid\Builder\FallbackBuilder;
use Akeeba\Passwordless\Ramsey\Uuid\Builder\UuidBuilderInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Codec\CodecInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Codec\GuidStringCodec;
use Akeeba\Passwordless\Ramsey\Uuid\Codec\StringCodec;
use Akeeba\Passwordless\Ramsey\Uuid\Converter\Number\GenericNumberConverter;
use Akeeba\Passwordless\Ramsey\Uuid\Converter\NumberConverterInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Converter\Time\GenericTimeConverter;
use Akeeba\Passwordless\Ramsey\Uuid\Converter\Time\PhpTimeConverter;
use Akeeba\Passwordless\Ramsey\Uuid\Converter\TimeConverterInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Generator\DceSecurityGenerator;
use Akeeba\Passwordless\Ramsey\Uuid\Generator\DceSecurityGeneratorInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Generator\NameGeneratorFactory;
use Akeeba\Passwordless\Ramsey\Uuid\Generator\NameGeneratorInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Generator\PeclUuidNameGenerator;
use Akeeba\Passwordless\Ramsey\Uuid\Generator\PeclUuidRandomGenerator;
use Akeeba\Passwordless\Ramsey\Uuid\Generator\PeclUuidTimeGenerator;
use Akeeba\Passwordless\Ramsey\Uuid\Generator\RandomGeneratorFactory;
use Akeeba\Passwordless\Ramsey\Uuid\Generator\RandomGeneratorInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Generator\TimeGeneratorFactory;
use Akeeba\Passwordless\Ramsey\Uuid\Generator\TimeGeneratorInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Guid\GuidBuilder;
use Akeeba\Passwordless\Ramsey\Uuid\Math\BrickMathCalculator;
use Akeeba\Passwordless\Ramsey\Uuid\Math\CalculatorInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Nonstandard\UuidBuilder as NonstandardUuidBuilder;
use Akeeba\Passwordless\Ramsey\Uuid\Provider\Dce\SystemDceSecurityProvider;
use Akeeba\Passwordless\Ramsey\Uuid\Provider\DceSecurityProviderInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Provider\Node\FallbackNodeProvider;
use Akeeba\Passwordless\Ramsey\Uuid\Provider\Node\NodeProviderCollection;
use Akeeba\Passwordless\Ramsey\Uuid\Provider\Node\RandomNodeProvider;
use Akeeba\Passwordless\Ramsey\Uuid\Provider\Node\SystemNodeProvider;
use Akeeba\Passwordless\Ramsey\Uuid\Provider\NodeProviderInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Provider\Time\SystemTimeProvider;
use Akeeba\Passwordless\Ramsey\Uuid\Provider\TimeProviderInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\UuidBuilder as Rfc4122UuidBuilder;
use Akeeba\Passwordless\Ramsey\Uuid\Validator\GenericValidator;
use Akeeba\Passwordless\Ramsey\Uuid\Validator\ValidatorInterface;

use const PHP_INT_SIZE;

/**
 * FeatureSet detects and exposes available features in the current environment
 *
 * A feature set is used by UuidFactory to determine the available features and
 * capabilities of the environment.
 */
class FeatureSet
{
    /**
     * @var bool
     */
    private $disableBigNumber = false;

    /**
     * @var bool
     */
    private $disable64Bit = false;

    /**
     * @var bool
     */
    private $ignoreSystemNode = false;

    /**
     * @var bool
     */
    private $enablePecl = false;

    /**
     * @var UuidBuilderInterface
     */
    private $builder;

    /**
     * @var CodecInterface
     */
    private $codec;

    /**
     * @var DceSecurityGeneratorInterface
     */
    private $dceSecurityGenerator;

    /**
     * @var NameGeneratorInterface
     */
    private $nameGenerator;

    /**
     * @var NodeProviderInterface
     */
    private $nodeProvider;

    /**
     * @var NumberConverterInterface
     */
    private $numberConverter;

    /**
     * @var TimeConverterInterface
     */
    private $timeConverter;

    /**
     * @var RandomGeneratorInterface
     */
    private $randomGenerator;

    /**
     * @var TimeGeneratorInterface
     */
    private $timeGenerator;

    /**
     * @var TimeProviderInterface
     */
    private $timeProvider;

    /**
     * @var ValidatorInterface
     */
    private $validator;

    /**
     * @var CalculatorInterface
     */
    private $calculator;

    /**
     * @param bool $useGuids True build UUIDs using the GuidStringCodec
     * @param bool $force32Bit True to force the use of 32-bit functionality
     *     (primarily for testing purposes)
     * @param bool $forceNoBigNumber True to disable the use of moontoast/math
     *     (primarily for testing purposes)
     * @param bool $ignoreSystemNode True to disable attempts to check for the
     *     system node ID (primarily for testing purposes)
     * @param bool $enablePecl True to enable the use of the PeclUuidTimeGenerator
     *     to generate version 1 UUIDs
     */
    public function __construct(
        bool $useGuids = false,
        bool $force32Bit = false,
        bool $forceNoBigNumber = false,
        bool $ignoreSystemNode = false,
        bool $enablePecl = false
    ) {
        $this->disableBigNumber = $forceNoBigNumber;
        $this->disable64Bit = $force32Bit;
        $this->ignoreSystemNode = $ignoreSystemNode;
        $this->enablePecl = $enablePecl;

        $this->setCalculator(new \Akeeba\Passwordless\Ramsey\Uuid\Math\BrickMathCalculator());
        $this->builder = $this->buildUuidBuilder($useGuids);
        $this->codec = $this->buildCodec($useGuids);
        $this->nodeProvider = $this->buildNodeProvider();
        $this->nameGenerator = $this->buildNameGenerator();
        $this->randomGenerator = $this->buildRandomGenerator();
        $this->setTimeProvider(new \Akeeba\Passwordless\Ramsey\Uuid\Provider\Time\SystemTimeProvider());
        $this->setDceSecurityProvider(new \Akeeba\Passwordless\Ramsey\Uuid\Provider\Dce\SystemDceSecurityProvider());
        $this->validator = new \Akeeba\Passwordless\Ramsey\Uuid\Validator\GenericValidator();
    }

    /**
     * Returns the builder configured for this environment
     */
    public function getBuilder(): \Akeeba\Passwordless\Ramsey\Uuid\Builder\UuidBuilderInterface
    {
        return $this->builder;
    }

    /**
     * Returns the calculator configured for this environment
     */
    public function getCalculator(): \Akeeba\Passwordless\Ramsey\Uuid\Math\CalculatorInterface
    {
        return $this->calculator;
    }

    /**
     * Returns the codec configured for this environment
     */
    public function getCodec(): \Akeeba\Passwordless\Ramsey\Uuid\Codec\CodecInterface
    {
        return $this->codec;
    }

    /**
     * Returns the DCE Security generator configured for this environment
     */
    public function getDceSecurityGenerator(): \Akeeba\Passwordless\Ramsey\Uuid\Generator\DceSecurityGeneratorInterface
    {
        return $this->dceSecurityGenerator;
    }

    /**
     * Returns the name generator configured for this environment
     */
    public function getNameGenerator(): \Akeeba\Passwordless\Ramsey\Uuid\Generator\NameGeneratorInterface
    {
        return $this->nameGenerator;
    }

    /**
     * Returns the node provider configured for this environment
     */
    public function getNodeProvider(): \Akeeba\Passwordless\Ramsey\Uuid\Provider\NodeProviderInterface
    {
        return $this->nodeProvider;
    }

    /**
     * Returns the number converter configured for this environment
     */
    public function getNumberConverter(): \Akeeba\Passwordless\Ramsey\Uuid\Converter\NumberConverterInterface
    {
        return $this->numberConverter;
    }

    /**
     * Returns the random generator configured for this environment
     */
    public function getRandomGenerator(): \Akeeba\Passwordless\Ramsey\Uuid\Generator\RandomGeneratorInterface
    {
        return $this->randomGenerator;
    }

    /**
     * Returns the time converter configured for this environment
     */
    public function getTimeConverter(): \Akeeba\Passwordless\Ramsey\Uuid\Converter\TimeConverterInterface
    {
        return $this->timeConverter;
    }

    /**
     * Returns the time generator configured for this environment
     */
    public function getTimeGenerator(): \Akeeba\Passwordless\Ramsey\Uuid\Generator\TimeGeneratorInterface
    {
        return $this->timeGenerator;
    }

    /**
     * Returns the validator configured for this environment
     */
    public function getValidator(): \Akeeba\Passwordless\Ramsey\Uuid\Validator\ValidatorInterface
    {
        return $this->validator;
    }

    /**
     * Sets the calculator to use in this environment
     */
    public function setCalculator(\Akeeba\Passwordless\Ramsey\Uuid\Math\CalculatorInterface $calculator): void
    {
        $this->calculator = $calculator;
        $this->numberConverter = $this->buildNumberConverter($calculator);
        $this->timeConverter = $this->buildTimeConverter($calculator);

        /** @psalm-suppress RedundantPropertyInitializationCheck */
        if (isset($this->timeProvider)) {
            $this->timeGenerator = $this->buildTimeGenerator($this->timeProvider);
        }
    }

    /**
     * Sets the DCE Security provider to use in this environment
     */
    public function setDceSecurityProvider(\Akeeba\Passwordless\Ramsey\Uuid\Provider\DceSecurityProviderInterface $dceSecurityProvider): void
    {
        $this->dceSecurityGenerator = $this->buildDceSecurityGenerator($dceSecurityProvider);
    }

    /**
     * Sets the node provider to use in this environment
     */
    public function setNodeProvider(\Akeeba\Passwordless\Ramsey\Uuid\Provider\NodeProviderInterface $nodeProvider): void
    {
        $this->nodeProvider = $nodeProvider;
        $this->timeGenerator = $this->buildTimeGenerator($this->timeProvider);
    }

    /**
     * Sets the time provider to use in this environment
     */
    public function setTimeProvider(\Akeeba\Passwordless\Ramsey\Uuid\Provider\TimeProviderInterface $timeProvider): void
    {
        $this->timeProvider = $timeProvider;
        $this->timeGenerator = $this->buildTimeGenerator($timeProvider);
    }

    /**
     * Set the validator to use in this environment
     */
    public function setValidator(\Akeeba\Passwordless\Ramsey\Uuid\Validator\ValidatorInterface $validator): void
    {
        $this->validator = $validator;
    }

    /**
     * Returns a codec configured for this environment
     *
     * @param bool $useGuids Whether to build UUIDs using the GuidStringCodec
     */
    private function buildCodec(bool $useGuids = false): \Akeeba\Passwordless\Ramsey\Uuid\Codec\CodecInterface
    {
        if ($useGuids) {
            return new \Akeeba\Passwordless\Ramsey\Uuid\Codec\GuidStringCodec($this->builder);
        }

        return new \Akeeba\Passwordless\Ramsey\Uuid\Codec\StringCodec($this->builder);
    }

    /**
     * Returns a DCE Security generator configured for this environment
     */
    private function buildDceSecurityGenerator(
        \Akeeba\Passwordless\Ramsey\Uuid\Provider\DceSecurityProviderInterface $dceSecurityProvider
    ): \Akeeba\Passwordless\Ramsey\Uuid\Generator\DceSecurityGeneratorInterface {
        return new \Akeeba\Passwordless\Ramsey\Uuid\Generator\DceSecurityGenerator(
            $this->numberConverter,
            $this->timeGenerator,
            $dceSecurityProvider
        );
    }

    /**
     * Returns a node provider configured for this environment
     */
    private function buildNodeProvider(): \Akeeba\Passwordless\Ramsey\Uuid\Provider\NodeProviderInterface
    {
        if ($this->ignoreSystemNode) {
            return new \Akeeba\Passwordless\Ramsey\Uuid\Provider\Node\RandomNodeProvider();
        }

        return new \Akeeba\Passwordless\Ramsey\Uuid\Provider\Node\FallbackNodeProvider(new \Akeeba\Passwordless\Ramsey\Uuid\Provider\Node\NodeProviderCollection([
            new \Akeeba\Passwordless\Ramsey\Uuid\Provider\Node\SystemNodeProvider(),
            new \Akeeba\Passwordless\Ramsey\Uuid\Provider\Node\RandomNodeProvider(),
        ]));
    }

    /**
     * Returns a number converter configured for this environment
     */
    private function buildNumberConverter(\Akeeba\Passwordless\Ramsey\Uuid\Math\CalculatorInterface $calculator): \Akeeba\Passwordless\Ramsey\Uuid\Converter\NumberConverterInterface
    {
        return new \Akeeba\Passwordless\Ramsey\Uuid\Converter\Number\GenericNumberConverter($calculator);
    }

    /**
     * Returns a random generator configured for this environment
     */
    private function buildRandomGenerator(): \Akeeba\Passwordless\Ramsey\Uuid\Generator\RandomGeneratorInterface
    {
        if ($this->enablePecl) {
            return new \Akeeba\Passwordless\Ramsey\Uuid\Generator\PeclUuidRandomGenerator();
        }

        return (new \Akeeba\Passwordless\Ramsey\Uuid\Generator\RandomGeneratorFactory())->getGenerator();
    }

    /**
     * Returns a time generator configured for this environment
     *
     * @param TimeProviderInterface $timeProvider The time provider to use with
     *     the time generator
     */
    private function buildTimeGenerator(\Akeeba\Passwordless\Ramsey\Uuid\Provider\TimeProviderInterface $timeProvider): \Akeeba\Passwordless\Ramsey\Uuid\Generator\TimeGeneratorInterface
    {
        if ($this->enablePecl) {
            return new \Akeeba\Passwordless\Ramsey\Uuid\Generator\PeclUuidTimeGenerator();
        }

        return (new \Akeeba\Passwordless\Ramsey\Uuid\Generator\TimeGeneratorFactory(
            $this->nodeProvider,
            $this->timeConverter,
            $timeProvider
        ))->getGenerator();
    }

    /**
     * Returns a name generator configured for this environment
     */
    private function buildNameGenerator(): \Akeeba\Passwordless\Ramsey\Uuid\Generator\NameGeneratorInterface
    {
        if ($this->enablePecl) {
            return new \Akeeba\Passwordless\Ramsey\Uuid\Generator\PeclUuidNameGenerator();
        }

        return (new \Akeeba\Passwordless\Ramsey\Uuid\Generator\NameGeneratorFactory())->getGenerator();
    }

    /**
     * Returns a time converter configured for this environment
     */
    private function buildTimeConverter(\Akeeba\Passwordless\Ramsey\Uuid\Math\CalculatorInterface $calculator): \Akeeba\Passwordless\Ramsey\Uuid\Converter\TimeConverterInterface
    {
        $genericConverter = new \Akeeba\Passwordless\Ramsey\Uuid\Converter\Time\GenericTimeConverter($calculator);

        if ($this->is64BitSystem()) {
            return new \Akeeba\Passwordless\Ramsey\Uuid\Converter\Time\PhpTimeConverter($calculator, $genericConverter);
        }

        return $genericConverter;
    }

    /**
     * Returns a UUID builder configured for this environment
     *
     * @param bool $useGuids Whether to build UUIDs using the GuidStringCodec
     */
    private function buildUuidBuilder(bool $useGuids = false): \Akeeba\Passwordless\Ramsey\Uuid\Builder\UuidBuilderInterface
    {
        if ($useGuids) {
            return new \Akeeba\Passwordless\Ramsey\Uuid\Guid\GuidBuilder($this->numberConverter, $this->timeConverter);
        }

        /** @psalm-suppress ImpureArgument */
        return new \Akeeba\Passwordless\Ramsey\Uuid\Builder\FallbackBuilder(new \Akeeba\Passwordless\Ramsey\Uuid\Builder\BuilderCollection([
            new \Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\UuidBuilder($this->numberConverter, $this->timeConverter),
            new \Akeeba\Passwordless\Ramsey\Uuid\Nonstandard\UuidBuilder($this->numberConverter, $this->timeConverter),
        ]));
    }

    /**
     * Returns true if the PHP build is 64-bit
     */
    private function is64BitSystem(): bool
    {
        return PHP_INT_SIZE === 8 && !$this->disable64Bit;
    }
}
