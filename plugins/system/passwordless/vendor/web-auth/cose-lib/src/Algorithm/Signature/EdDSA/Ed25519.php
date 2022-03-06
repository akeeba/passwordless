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

namespace Akeeba\Passwordless\Cose\Algorithm\Signature\EdDSA;

final class Ed25519 extends \Akeeba\Passwordless\Cose\Algorithm\Signature\EdDSA\EdDSA
{
    public const ID = -8;

    public static function identifier(): int
    {
        return self::ID;
    }
}
