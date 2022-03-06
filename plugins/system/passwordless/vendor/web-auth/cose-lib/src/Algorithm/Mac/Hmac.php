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

namespace Akeeba\Passwordless\Cose\Algorithm\Mac;

use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use Akeeba\Passwordless\Cose\Key\Key;

abstract class Hmac implements \Akeeba\Passwordless\Cose\Algorithm\Mac\Mac
{
    public function hash(string $data, \Akeeba\Passwordless\Cose\Key\Key $key): string
    {
        $this->checKey($key);
        $signature = hash_hmac($this->getHashAlgorithm(), $data, $key->get(-1), true);

        return mb_substr($signature, 0, intdiv($this->getSignatureLength(), 8), '8bit');
    }

    public function verify(string $data, \Akeeba\Passwordless\Cose\Key\Key $key, string $signature): bool
    {
        return hash_equals($this->hash($data, $key), $signature);
    }

    abstract protected function getHashAlgorithm(): string;

    abstract protected function getSignatureLength(): int;

    private function checKey(\Akeeba\Passwordless\Cose\Key\Key $key): void
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq($key->type(), 4, 'Invalid key. Must be of type symmetric');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($key->has(-1), 'Invalid key. The value of the key is missing');
    }
}
