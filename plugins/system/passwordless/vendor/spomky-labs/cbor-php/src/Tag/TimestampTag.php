<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Akeeba\Passwordless\CBOR\Tag;

use Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject;
use Akeeba\Passwordless\CBOR\NegativeIntegerObject;
use Akeeba\Passwordless\CBOR\Normalizable;
use Akeeba\Passwordless\CBOR\OtherObject\DoublePrecisionFloatObject;
use Akeeba\Passwordless\CBOR\OtherObject\HalfPrecisionFloatObject;
use Akeeba\Passwordless\CBOR\OtherObject\SinglePrecisionFloatObject;
use Akeeba\Passwordless\CBOR\Tag;
use Akeeba\Passwordless\CBOR\UnsignedIntegerObject;
use DateTimeImmutable;
use DateTimeInterface;
use InvalidArgumentException;
use const STR_PAD_RIGHT;

final class TimestampTag extends \Akeeba\Passwordless\CBOR\Tag implements \Akeeba\Passwordless\CBOR\Normalizable
{
    public function __construct(int $additionalInformation, ?string $data, \Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object)
    {
        if (! $object instanceof \Akeeba\Passwordless\CBOR\UnsignedIntegerObject && ! $object instanceof \Akeeba\Passwordless\CBOR\NegativeIntegerObject && ! $object instanceof \Akeeba\Passwordless\CBOR\OtherObject\HalfPrecisionFloatObject && ! $object instanceof \Akeeba\Passwordless\CBOR\OtherObject\SinglePrecisionFloatObject && ! $object instanceof \Akeeba\Passwordless\CBOR\OtherObject\DoublePrecisionFloatObject) {
            throw new InvalidArgumentException('This tag only accepts integer-based or float-based objects.');
        }
        parent::__construct($additionalInformation, $data, $object);
    }

    public static function getTagId(): int
    {
        return self::TAG_EPOCH_DATETIME;
    }

    public static function createFromLoadedData(int $additionalInformation, ?string $data, \Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object): \Akeeba\Passwordless\CBOR\Tag
    {
        return new self($additionalInformation, $data, $object);
    }

    public static function create(\Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object): \Akeeba\Passwordless\CBOR\Tag
    {
        [$ai, $data] = self::determineComponents(self::TAG_EPOCH_DATETIME);

        return new self($ai, $data, $object);
    }

    public function normalize(): DateTimeInterface
    {
        $object = $this->object;

        switch (true) {
            case $object instanceof \Akeeba\Passwordless\CBOR\UnsignedIntegerObject:
            case $object instanceof \Akeeba\Passwordless\CBOR\NegativeIntegerObject:
                $formatted = DateTimeImmutable::createFromFormat('U', $object->normalize());

            break;
            case $object instanceof \Akeeba\Passwordless\CBOR\OtherObject\HalfPrecisionFloatObject:
            case $object instanceof \Akeeba\Passwordless\CBOR\OtherObject\SinglePrecisionFloatObject:
            case $object instanceof \Akeeba\Passwordless\CBOR\OtherObject\DoublePrecisionFloatObject:
                $value = (string) $object->normalize();
                $parts = explode('.', $value);
                if (isset($parts[1])) {
                    if (mb_strlen($parts[1], '8bit') > 6) {
                        $parts[1] = mb_substr($parts[1], 0, 6, '8bit');
                    } else {
                        $parts[1] = str_pad($parts[1], 6, '0', STR_PAD_RIGHT);
                    }
                }
                $formatted = DateTimeImmutable::createFromFormat('U.u', implode('.', $parts));

                break;
            default:
                throw new InvalidArgumentException('Unable to normalize the object');
        }

        if ($formatted === false) {
            throw new InvalidArgumentException('Invalid data. Cannot be converted into a datetime object');
        }

        return $formatted;
    }

    /**
     * @deprecated The method will be removed on v3.0. Please rely on the CBOR\Normalizable interface
     */
    public function getNormalizedData(bool $ignoreTags = false)
    {
        if ($ignoreTags) {
            return $this->object->getNormalizedData($ignoreTags);
        }
        switch (true) {
            case $this->object instanceof \Akeeba\Passwordless\CBOR\UnsignedIntegerObject:
            case $this->object instanceof \Akeeba\Passwordless\CBOR\NegativeIntegerObject:
            case $this->object instanceof \Akeeba\Passwordless\CBOR\OtherObject\HalfPrecisionFloatObject:
            case $this->object instanceof \Akeeba\Passwordless\CBOR\OtherObject\SinglePrecisionFloatObject:
            case $this->object instanceof \Akeeba\Passwordless\CBOR\OtherObject\DoublePrecisionFloatObject:
                return $this->normalize();
            default:
                return $this->object->getNormalizedData($ignoreTags);
        }
    }
}
