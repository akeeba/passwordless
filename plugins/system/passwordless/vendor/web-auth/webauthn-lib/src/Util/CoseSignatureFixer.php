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

namespace Akeeba\Passwordless\Webauthn\Util;

use Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA;
use Akeeba\Passwordless\Cose\Algorithm\Signature\Signature;

/**
 * This class fixes the signature of the ECDSA based algorithms.
 *
 * @internal
 *
 * @see https://www.w3.org/TR/webauthn/#signature-attestation-types
 */
abstract class CoseSignatureFixer
{
    public static function fix(string $signature, \Akeeba\Passwordless\Cose\Algorithm\Signature\Signature $algorithm): string
    {
        switch ($algorithm::identifier()) {
            case \Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA\ES256K::ID:
            case \Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA\ES256::ID:
                if (64 === mb_strlen($signature, '8bit')) {
                    return $signature;
                }

                return \Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA\ECSignature::fromAsn1($signature, 64); //TODO: fix this hardcoded value by adding a dedicated method for the algorithms
            case \Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA\ES384::ID:
                if (96 === mb_strlen($signature, '8bit')) {
                    return $signature;
                }

                return \Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA\ECSignature::fromAsn1($signature, 96);
            case \Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA\ES512::ID:
                if (132 === mb_strlen($signature, '8bit')) {
                    return $signature;
                }

                return \Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA\ECSignature::fromAsn1($signature, 132);
        }

        return $signature;
    }
}
