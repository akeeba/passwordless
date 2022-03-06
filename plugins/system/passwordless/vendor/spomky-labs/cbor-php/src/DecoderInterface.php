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

interface DecoderInterface
{
    public function decode(\Akeeba\Passwordless\CBOR\Stream $stream): \Akeeba\Passwordless\CBOR\CBORObject;
}
