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

use Akeeba\Passwordless\CBOR\ByteStringObject;
use Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject;
use Akeeba\Passwordless\CBOR\IndefiniteLengthByteStringObject;
use Akeeba\Passwordless\CBOR\IndefiniteLengthTextStringObject;
use Akeeba\Passwordless\CBOR\Tag;
use Akeeba\Passwordless\CBOR\TextStringObject;
use Akeeba\Passwordless\CBOR\Utils;

final class Base64UrlEncodingTag extends \Akeeba\Passwordless\CBOR\Tag
{
    public static function getTagId(): int
    {
        return self::TAG_ENCODED_BASE64_URL;
    }

    public static function createFromLoadedData(int $additionalInformation, ?string $data, \Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object): \Akeeba\Passwordless\CBOR\Tag
    {
        return new self($additionalInformation, $data, $object);
    }

    public static function create(\Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object): \Akeeba\Passwordless\CBOR\Tag
    {
        [$ai, $data] = self::determineComponents(self::TAG_ENCODED_BASE64_URL);

        return new self($ai, $data, $object);
    }

    /**
     * @deprecated The method will be removed on v3.0. Please rely on the CBOR\Normalizable interface
     */
    public function getNormalizedData(bool $ignoreTags = false)
    {
        if ($ignoreTags) {
            return $this->object->getNormalizedData($ignoreTags);
        }

        if (! $this->object instanceof \Akeeba\Passwordless\CBOR\ByteStringObject && ! $this->object instanceof \Akeeba\Passwordless\CBOR\IndefiniteLengthByteStringObject && ! $this->object instanceof \Akeeba\Passwordless\CBOR\TextStringObject && ! $this->object instanceof \Akeeba\Passwordless\CBOR\IndefiniteLengthTextStringObject) {
            return $this->object->getNormalizedData($ignoreTags);
        }

        return \Akeeba\Passwordless\CBOR\Utils::decode($this->object->getNormalizedData($ignoreTags));
    }
}
