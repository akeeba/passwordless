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

use Akeeba\Passwordless\Ramsey\Uuid\Codec\CodecInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Converter\NumberConverterInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Converter\TimeConverterInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Exception\InvalidArgumentException;
use Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\FieldsInterface as Rfc4122FieldsInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Uuid;

/**
 * Version 3 UUIDs are named-based, using combination of a namespace and name
 * that are hashed into a 128-bit unsigned integer using MD5
 *
 * @psalm-immutable
 */
final class UuidV3 extends \Akeeba\Passwordless\Ramsey\Uuid\Uuid implements \Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\UuidInterface
{
    /**
     * Creates a version 3 (name-based, MD5-hashed) UUID
     *
     * @param Rfc4122FieldsInterface $fields The fields from which to construct a UUID
     * @param NumberConverterInterface $numberConverter The number converter to use
     *     for converting hex values to/from integers
     * @param CodecInterface $codec The codec to use when encoding or decoding
     *     UUID strings
     * @param TimeConverterInterface $timeConverter The time converter to use
     *     for converting timestamps extracted from a UUID to unix timestamps
     */
    public function __construct(
        \Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\FieldsInterface $fields,
        \Akeeba\Passwordless\Ramsey\Uuid\Converter\NumberConverterInterface $numberConverter,
        \Akeeba\Passwordless\Ramsey\Uuid\Codec\CodecInterface $codec,
        \Akeeba\Passwordless\Ramsey\Uuid\Converter\TimeConverterInterface $timeConverter
    ) {
        if ($fields->getVersion() !== \Akeeba\Passwordless\Ramsey\Uuid\Uuid::UUID_TYPE_HASH_MD5) {
            throw new \Akeeba\Passwordless\Ramsey\Uuid\Exception\InvalidArgumentException(
                'Fields used to create a UuidV3 must represent a '
                . 'version 3 (name-based, MD5-hashed) UUID'
            );
        }

        parent::__construct($fields, $numberConverter, $codec, $timeConverter);
    }
}
