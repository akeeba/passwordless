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

use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;

class ManagerFactory
{
    /**
     * @var Algorithm[]
     */
    private $algorithms = [];

    public function add(string $alias, \Akeeba\Passwordless\Cose\Algorithm\Algorithm $algorithm): void
    {
        $this->algorithms[$alias] = $algorithm;
    }

    public function list(): iterable
    {
        yield from array_keys($this->algorithms);
    }

    public function all(): iterable
    {
        yield from array_keys($this->algorithms);
    }

    public function create(array $aliases): \Akeeba\Passwordless\Cose\Algorithm\Manager
    {
        $manager = new \Akeeba\Passwordless\Cose\Algorithm\Manager();
        foreach ($aliases as $alias) {
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($this->algorithms, $alias, sprintf('The algorithm with alias "%s" is not supported', $alias));
            $manager->add($this->algorithms[$alias]);
        }

        return $manager;
    }
}
