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

use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use Akeeba\Passwordless\Cose\Algorithm\Signature\Signature;
use Akeeba\Passwordless\Cose\Key\Ec2Key;
use Akeeba\Passwordless\Cose\Key\Key;

abstract class ECDSA implements \Akeeba\Passwordless\Cose\Algorithm\Signature\Signature
{
    public function sign(string $data, \Akeeba\Passwordless\Cose\Key\Key $key): string
    {
        $key = $this->handleKey($key);
        openssl_sign($data, $signature, $key->asPEM(), $this->getHashAlgorithm());

        return \Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA\ECSignature::fromAsn1($signature, $this->getSignaturePartLength());
    }

    public function verify(string $data, \Akeeba\Passwordless\Cose\Key\Key $key, string $signature): bool
    {
        $key = $this->handleKey($key);
        $publicKey = $key->toPublic();
        $signature = \Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA\ECSignature::toAsn1($signature, $this->getSignaturePartLength());

        return 1 === openssl_verify($data, $signature, $publicKey->asPEM(), $this->getHashAlgorithm());
    }

    abstract protected function getCurve(): int;

    abstract protected function getHashAlgorithm(): int;

    abstract protected function getSignaturePartLength(): int;

    private function handleKey(\Akeeba\Passwordless\Cose\Key\Key $key): \Akeeba\Passwordless\Cose\Key\Ec2Key
    {
        $key = new \Akeeba\Passwordless\Cose\Key\Ec2Key($key->getData());
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq($key->curve(), $this->getCurve(), 'This key cannot be used with this algorithm');

        return $key;
    }
}
