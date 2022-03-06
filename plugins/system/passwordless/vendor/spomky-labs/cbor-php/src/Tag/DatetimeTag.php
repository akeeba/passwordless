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
use Akeeba\Passwordless\CBOR\IndefiniteLengthTextStringObject;
use Akeeba\Passwordless\CBOR\Normalizable;
use Akeeba\Passwordless\CBOR\Tag;
use Akeeba\Passwordless\CBOR\TextStringObject;
use const DATE_RFC3339;
use DateTimeImmutable;
use DateTimeInterface;
use InvalidArgumentException;

/**
 * @final
 */
class DatetimeTag extends \Akeeba\Passwordless\CBOR\Tag implements \Akeeba\Passwordless\CBOR\Normalizable
{
    public function __construct(int $additionalInformation, ?string $data, \Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object)
    {
        if (! $object instanceof \Akeeba\Passwordless\CBOR\TextStringObject && ! $object instanceof \Akeeba\Passwordless\CBOR\IndefiniteLengthTextStringObject) {
            throw new InvalidArgumentException('This tag only accepts a Byte String object.');
        }
        parent::__construct($additionalInformation, $data, $object);
    }

    public static function getTagId(): int
    {
        return self::TAG_STANDARD_DATETIME;
    }

    public static function createFromLoadedData(int $additionalInformation, ?string $data, \Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object): \Akeeba\Passwordless\CBOR\Tag
    {
        return new self($additionalInformation, $data, $object);
    }

    public static function create(\Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object): \Akeeba\Passwordless\CBOR\Tag
    {
        [$ai, $data] = self::determineComponents(self::TAG_STANDARD_DATETIME);

        return new self($ai, $data, $object);
    }

    public function normalize(): DateTimeInterface
    {
        /** @var TextStringObject|IndefiniteLengthTextStringObject $object */
        $object = $this->object;
        $result = DateTimeImmutable::createFromFormat(DATE_RFC3339, $object->normalize());
        if ($result !== false) {
            return $result;
        }

        $formatted = DateTimeImmutable::createFromFormat('Y-m-d\TH:i:s.uP', $object->normalize());
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

        return $this->normalize();
    }
}
