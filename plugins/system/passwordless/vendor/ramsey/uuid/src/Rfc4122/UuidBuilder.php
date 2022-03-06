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

namespace Akeeba\Passwordless\Ramsey\Uuid\Rfc4122;

use Akeeba\Passwordless\Ramsey\Uuid\Builder\UuidBuilderInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Codec\CodecInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Converter\NumberConverterInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Converter\TimeConverterInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Exception\UnableToBuildUuidException;
use Akeeba\Passwordless\Ramsey\Uuid\Exception\UnsupportedOperationException;
use Akeeba\Passwordless\Ramsey\Uuid\Nonstandard\UuidV6;
use Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\UuidInterface as Rfc4122UuidInterface;
use Akeeba\Passwordless\Ramsey\Uuid\UuidInterface;
use Throwable;

/**
 * UuidBuilder builds instances of RFC 4122 UUIDs
 *
 * @psalm-immutable
 */
class UuidBuilder implements \Akeeba\Passwordless\Ramsey\Uuid\Builder\UuidBuilderInterface
{
    /**
     * @var NumberConverterInterface
     */
    private $numberConverter;

    /**
     * @var TimeConverterInterface
     */
    private $timeConverter;

    /**
     * Constructs the DefaultUuidBuilder
     *
     * @param NumberConverterInterface $numberConverter The number converter to
     *     use when constructing the Uuid
     * @param TimeConverterInterface $timeConverter The time converter to use
     *     for converting timestamps extracted from a UUID to Unix timestamps
     */
    public function __construct(
        \Akeeba\Passwordless\Ramsey\Uuid\Converter\NumberConverterInterface $numberConverter,
        \Akeeba\Passwordless\Ramsey\Uuid\Converter\TimeConverterInterface $timeConverter
    ) {
        $this->numberConverter = $numberConverter;
        $this->timeConverter = $timeConverter;
    }

    /**
     * Builds and returns a Uuid
     *
     * @param CodecInterface $codec The codec to use for building this Uuid instance
     * @param string $bytes The byte string from which to construct a UUID
     *
     * @return Rfc4122UuidInterface UuidBuilder returns instances of Rfc4122UuidInterface
     *
     * @psalm-pure
     */
    public function build(\Akeeba\Passwordless\Ramsey\Uuid\Codec\CodecInterface $codec, string $bytes): \Akeeba\Passwordless\Ramsey\Uuid\UuidInterface
    {
        try {
            $fields = $this->buildFields($bytes);

            if ($fields->isNil()) {
                return new \Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\NilUuid($fields, $this->numberConverter, $codec, $this->timeConverter);
            }

            switch ($fields->getVersion()) {
                case 1:
                    return new \Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\UuidV1($fields, $this->numberConverter, $codec, $this->timeConverter);
                case 2:
                    return new \Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\UuidV2($fields, $this->numberConverter, $codec, $this->timeConverter);
                case 3:
                    return new \Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\UuidV3($fields, $this->numberConverter, $codec, $this->timeConverter);
                case 4:
                    return new \Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\UuidV4($fields, $this->numberConverter, $codec, $this->timeConverter);
                case 5:
                    return new \Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\UuidV5($fields, $this->numberConverter, $codec, $this->timeConverter);
                case 6:
                    return new \Akeeba\Passwordless\Ramsey\Uuid\Nonstandard\UuidV6($fields, $this->numberConverter, $codec, $this->timeConverter);
            }

            throw new \Akeeba\Passwordless\Ramsey\Uuid\Exception\UnsupportedOperationException(
                'The UUID version in the given fields is not supported '
                . 'by this UUID builder'
            );
        } catch (Throwable $e) {
            throw new \Akeeba\Passwordless\Ramsey\Uuid\Exception\UnableToBuildUuidException($e->getMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * Proxy method to allow injecting a mock, for testing
     */
    protected function buildFields(string $bytes): \Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\FieldsInterface
    {
        return new \Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\Fields($bytes);
    }
}
