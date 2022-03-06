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

namespace Akeeba\Passwordless\CBOR;

class MapItem
{
    /**
     * @var CBORObject
     */
    private $key;

    /**
     * @var CBORObject
     */
    private $value;

    public function __construct(\Akeeba\Passwordless\CBOR\CBORObject $key, \Akeeba\Passwordless\CBOR\CBORObject $value)
    {
        $this->key = $key;
        $this->value = $value;
    }

    public static function create(\Akeeba\Passwordless\CBOR\CBORObject $key, \Akeeba\Passwordless\CBOR\CBORObject $value): self
    {
        return new self($key, $value);
    }

    public function getKey(): \Akeeba\Passwordless\CBOR\CBORObject
    {
        return $this->key;
    }

    public function getValue(): \Akeeba\Passwordless\CBOR\CBORObject
    {
        return $this->value;
    }
}
