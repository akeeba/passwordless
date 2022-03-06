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

namespace Akeeba\Passwordless\Webauthn\AuthenticationExtensions;

use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject;
use Akeeba\Passwordless\CBOR\MapObject;

abstract class AuthenticationExtensionsClientOutputsLoader
{
    public static function load(\Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object): \Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isInstanceOf($object, \Akeeba\Passwordless\CBOR\MapObject::class, 'Invalid extension object');
        $data = $object->getNormalizedData();
        $extensions = new \Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs();
        foreach ($data as $key => $value) {
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::string($key, 'Invalid extension key');
            $extensions->add(new \Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtension($key, $value));
        }

        return $extensions;
    }
}
