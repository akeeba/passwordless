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

namespace Akeeba\Passwordless\Cose\Algorithm;

use function array_key_exists;
use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;

class Manager
{
    /**
     * @var Algorithm[]
     */
    private $algorithms = [];

    public function add(\Akeeba\Passwordless\Cose\Algorithm\Algorithm $algorithm): void
    {
        $identifier = $algorithm::identifier();
        $this->algorithms[$identifier] = $algorithm;
    }

    public function list(): iterable
    {
        yield from array_keys($this->algorithms);
    }

    /**
     * @return Algorithm[]
     */
    public function all(): iterable
    {
        yield from $this->algorithms;
    }

    public function has(int $identifier): bool
    {
        return array_key_exists($identifier, $this->algorithms);
    }

    public function get(int $identifier): \Akeeba\Passwordless\Cose\Algorithm\Algorithm
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($this->has($identifier), 'Unsupported algorithm');

        return $this->algorithms[$identifier];
    }
}
