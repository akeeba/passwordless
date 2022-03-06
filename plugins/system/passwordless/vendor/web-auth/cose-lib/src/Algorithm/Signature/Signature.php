<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Akeeba\Passwordless\Cose\Algorithm\Signature;

use Akeeba\Passwordless\Cose\Algorithm\Algorithm;
use Akeeba\Passwordless\Cose\Key\Key;

interface Signature extends \Akeeba\Passwordless\Cose\Algorithm\Algorithm
{
    public function sign(string $data, \Akeeba\Passwordless\Cose\Key\Key $key): string;

    public function verify(string $data, \Akeeba\Passwordless\Cose\Key\Key $key, string $signature): bool;
}
