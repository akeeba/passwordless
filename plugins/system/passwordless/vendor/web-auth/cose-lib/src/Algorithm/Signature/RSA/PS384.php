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

namespace Akeeba\Passwordless\Cose\Algorithm\Signature\RSA;

use Akeeba\Passwordless\Cose\Hash;

final class PS384 extends \Akeeba\Passwordless\Cose\Algorithm\Signature\RSA\PSSRSA
{
    public const ID = -38;

    public static function identifier(): int
    {
        return self::ID;
    }

    protected function getHashAlgorithm(): \Akeeba\Passwordless\Cose\Hash
    {
        return \Akeeba\Passwordless\Cose\Hash::sha384();
    }
}
