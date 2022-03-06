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

use \Akeeba\Passwordless\CBOR\CBORObject;
use Akeeba\Passwordless\CBOR\Tag;

interface TagManagerInterface
{
    public function createObjectForValue(int $additionalInformation, ?string $data, \Akeeba\Passwordless\CBOR\CBORObject $object): \Akeeba\Passwordless\CBOR\Tag;
}
