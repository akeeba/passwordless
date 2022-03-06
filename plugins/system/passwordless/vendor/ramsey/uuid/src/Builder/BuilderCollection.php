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

namespace Akeeba\Passwordless\Ramsey\Uuid\Builder;

use Akeeba\Passwordless\Ramsey\Collection\AbstractCollection;
use Akeeba\Passwordless\Ramsey\Uuid\Converter\Number\GenericNumberConverter;
use Akeeba\Passwordless\Ramsey\Uuid\Converter\Time\GenericTimeConverter;
use Akeeba\Passwordless\Ramsey\Uuid\Converter\Time\PhpTimeConverter;
use Akeeba\Passwordless\Ramsey\Uuid\Guid\GuidBuilder;
use Akeeba\Passwordless\Ramsey\Uuid\Math\BrickMathCalculator;
use Akeeba\Passwordless\Ramsey\Uuid\Nonstandard\UuidBuilder as NonstandardUuidBuilder;
use Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\UuidBuilder as Rfc4122UuidBuilder;
use Traversable;

/**
 * A collection of UuidBuilderInterface objects
 *
 * @extends AbstractCollection<UuidBuilderInterface>
 */
class BuilderCollection extends \Akeeba\Passwordless\Ramsey\Collection\AbstractCollection
{
    public function getType(): string
    {
        return \Akeeba\Passwordless\Ramsey\Uuid\Builder\UuidBuilderInterface::class;
    }

    /**
     * @psalm-mutation-free
     * @psalm-suppress ImpureMethodCall
     * @psalm-suppress InvalidTemplateParam
     */
    public function getIterator(): Traversable
    {
        return parent::getIterator();
    }

    /**
     * Re-constructs the object from its serialized form
     *
     * @param string $serialized The serialized PHP string to unserialize into
     *     a UuidInterface instance
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.ParameterTypeHint.MissingNativeTypeHint
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    public function unserialize($serialized): void
    {
        /** @var array<array-key, UuidBuilderInterface> $data */
        $data = unserialize($serialized, [
            'allowed_classes' => [
                \Akeeba\Passwordless\Ramsey\Uuid\Math\BrickMathCalculator::class,
                \Akeeba\Passwordless\Ramsey\Uuid\Converter\Number\GenericNumberConverter::class,
                \Akeeba\Passwordless\Ramsey\Uuid\Converter\Time\GenericTimeConverter::class,
                \Akeeba\Passwordless\Ramsey\Uuid\Guid\GuidBuilder::class,
                \Akeeba\Passwordless\Ramsey\Uuid\Nonstandard\UuidBuilder::class,
                \Akeeba\Passwordless\Ramsey\Uuid\Converter\Time\PhpTimeConverter::class,
                \Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\UuidBuilder::class,
            ],
        ]);

        $this->data = array_filter(
            $data,
            function ($unserialized): bool {
                return $unserialized instanceof \Akeeba\Passwordless\Ramsey\Uuid\Builder\UuidBuilderInterface;
            }
        );
    }
}
