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
use InvalidArgumentException;

final class UriTag extends \Akeeba\Passwordless\CBOR\Tag implements \Akeeba\Passwordless\CBOR\Normalizable
{
    public function __construct(int $additionalInformation, ?string $data, \Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object)
    {
        if (! $object instanceof \Akeeba\Passwordless\CBOR\TextStringObject && ! $object instanceof \Akeeba\Passwordless\CBOR\IndefiniteLengthTextStringObject) {
            throw new InvalidArgumentException('This tag only accepts a Text String object.');
        }

        parent::__construct($additionalInformation, $data, $object);
    }

    public static function getTagId(): int
    {
        return self::TAG_URI;
    }

    public static function createFromLoadedData(int $additionalInformation, ?string $data, \Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object): \Akeeba\Passwordless\CBOR\Tag
    {
        return new self($additionalInformation, $data, $object);
    }

    public static function create(\Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object): \Akeeba\Passwordless\CBOR\Tag
    {
        [$ai, $data] = self::determineComponents(self::TAG_URI);

        return new self($ai, $data, $object);
    }

    public function normalize(): string
    {
        /** @var TextStringObject|IndefiniteLengthTextStringObject $object */
        $object = $this->object;

        return $object->normalize();
    }

    /**
     * @deprecated The method will be removed on v3.0. Please rely on the CBOR\Normalizable interface
     */
    public function getNormalizedData(bool $ignoreTags = false)
    {
        return $this->object->getNormalizedData($ignoreTags);
    }
}
