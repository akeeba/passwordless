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

use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use Akeeba\Passwordless\Cose\Algorithm\Signature\Signature;
use Akeeba\Passwordless\Cose\Algorithms;
use Akeeba\Passwordless\Cose\Key\Key;
use Akeeba\Passwordless\Cose\Key\OkpKey;
use InvalidArgumentException;
use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_verify_detached;

class EdDSA implements \Akeeba\Passwordless\Cose\Algorithm\Signature\Signature
{
    public function sign(string $data, \Akeeba\Passwordless\Cose\Key\Key $key): string
    {
        $key = $this->handleKey($key);
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($key->isPrivate(), 'The key is not private');

        $x = $key->x();
        $d = $key->d();
        $secret = $d.$x;

        switch ($key->curve()) {
            case \Akeeba\Passwordless\Cose\Key\OkpKey::CURVE_ED25519:
                return sodium_crypto_sign_detached($data, $secret);
            default:
                throw new InvalidArgumentException('Unsupported curve');
        }
    }

    public function verify(string $data, \Akeeba\Passwordless\Cose\Key\Key $key, string $signature): bool
    {
        $key = $this->handleKey($key);

        switch ($key->curve()) {
            case \Akeeba\Passwordless\Cose\Key\OkpKey::CURVE_ED25519:
                return sodium_crypto_sign_verify_detached($signature, $data, $key->x());
            default:
                throw new InvalidArgumentException('Unsupported curve');
        }
    }

    public static function identifier(): int
    {
        return \Akeeba\Passwordless\Cose\Algorithms::COSE_ALGORITHM_EdDSA;
    }

    private function handleKey(\Akeeba\Passwordless\Cose\Key\Key $key): \Akeeba\Passwordless\Cose\Key\OkpKey
    {
        return new \Akeeba\Passwordless\Cose\Key\OkpKey($key->getData());
    }
}
