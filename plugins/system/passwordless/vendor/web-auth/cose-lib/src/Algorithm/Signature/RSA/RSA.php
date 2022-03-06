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

use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use Akeeba\Passwordless\Cose\Algorithm\Signature\Signature;
use Akeeba\Passwordless\Cose\Key\Key;
use Akeeba\Passwordless\Cose\Key\RsaKey;
use InvalidArgumentException;

abstract class RSA implements \Akeeba\Passwordless\Cose\Algorithm\Signature\Signature
{
    public function sign(string $data, \Akeeba\Passwordless\Cose\Key\Key $key): string
    {
        $key = $this->handleKey($key);
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($key->isPrivate(), 'The key is not private');

        if (false === openssl_sign($data, $signature, $key->asPem(), $this->getHashAlgorithm())) {
            throw new InvalidArgumentException('Unable to sign the data');
        }

        return $signature;
    }

    public function verify(string $data, \Akeeba\Passwordless\Cose\Key\Key $key, string $signature): bool
    {
        $key = $this->handleKey($key);

        return 1 === openssl_verify($data, $signature, $key->asPem(), $this->getHashAlgorithm());
    }

    abstract protected function getHashAlgorithm(): int;

    private function handleKey(\Akeeba\Passwordless\Cose\Key\Key $key): \Akeeba\Passwordless\Cose\Key\RsaKey
    {
        return new \Akeeba\Passwordless\Cose\Key\RsaKey($key->getData());
    }
}
