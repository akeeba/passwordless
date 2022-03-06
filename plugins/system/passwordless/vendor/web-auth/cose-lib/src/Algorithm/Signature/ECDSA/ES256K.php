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

namespace Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA;

use Akeeba\Passwordless\Cose\Key\Ec2Key;

final class ES256K extends \Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA\ECDSA
{
    public const ID = -46;

    public static function identifier(): int
    {
        return self::ID;
    }

    protected function getHashAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    protected function getCurve(): int
    {
        return \Akeeba\Passwordless\Cose\Key\Ec2Key::CURVE_P256K;
    }

    protected function getSignaturePartLength(): int
    {
        return 64;
    }
}
