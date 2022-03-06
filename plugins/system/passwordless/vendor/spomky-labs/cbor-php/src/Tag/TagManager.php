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

use function array_key_exists;
use \Akeeba\Passwordless\CBOR\CBORObject;
use Akeeba\Passwordless\CBOR\Tag;
use Akeeba\Passwordless\CBOR\Utils;
use InvalidArgumentException;

/**
 * @final
 */
class TagManager implements \Akeeba\Passwordless\CBOR\Tag\TagManagerInterface
{
    /**
     * @var string[]
     */
    private $classes = [];

    public static function create(): self
    {
        return new self();
    }

    public function add(string $class): self
    {
        if ($class::getTagId() < 0) {
            throw new InvalidArgumentException('Invalid tag ID.');
        }
        $this->classes[$class::getTagId()] = $class;

        return $this;
    }

    public function getClassForValue(int $value): string
    {
        return array_key_exists($value, $this->classes) ? $this->classes[$value] : \Akeeba\Passwordless\CBOR\Tag\GenericTag::class;
    }

    public function createObjectForValue(int $additionalInformation, ?string $data, \Akeeba\Passwordless\CBOR\CBORObject $object): \Akeeba\Passwordless\CBOR\Tag
    {
        $value = $additionalInformation;
        if ($additionalInformation >= 24) {
            \Akeeba\Passwordless\CBOR\Utils::assertString($data, 'Invalid data');
            $value = \Akeeba\Passwordless\CBOR\Utils::binToInt($data);
        }
        /** @var Tag $class */
        $class = $this->getClassForValue($value);

        return $class::createFromLoadedData($additionalInformation, $data, $object);
    }
}
