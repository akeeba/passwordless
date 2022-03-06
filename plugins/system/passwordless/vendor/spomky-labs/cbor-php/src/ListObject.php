<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Akeeba\Passwordless\CBOR;

use function array_key_exists;
use ArrayAccess;
use ArrayIterator;
use function count;
use Countable;
use InvalidArgumentException;
use Iterator;
use IteratorAggregate;

/**
 * @phpstan-implements ArrayAccess<int, CBORObject>
 * @phpstan-implements IteratorAggregate<int, CBORObject>
 */
class ListObject extends \Akeeba\Passwordless\CBOR\AbstractAkeeba\Passwordless\CBORObject implements Countable, IteratorAggregate, \Akeeba\Passwordless\CBOR\Normalizable, ArrayAccess
{
    private const MAJOR_TYPE = self::MAJOR_TYPE_LIST;

    /**
     * @var CBORObject[]
     */
    private $data;

    /**
     * @var string|null
     */
    private $length;

    /**
     * @param CBORObject[] $data
     */
    public function __construct(array $data = [])
    {
        [$additionalInformation, $length] = \Akeeba\Passwordless\CBOR\LengthCalculator::getLengthOfArray($data);
        array_map(static function ($item): void {
            if (! $item instanceof \Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject) {
                throw new InvalidArgumentException('The list must contain only CBORObject objects.');
            }
        }, $data);

        parent::__construct(self::MAJOR_TYPE, $additionalInformation);
        $this->data = array_values($data);
        $this->length = $length;
    }

    public function __toString(): string
    {
        $result = parent::__toString();
        if ($this->length !== null) {
            $result .= $this->length;
        }
        foreach ($this->data as $object) {
            $result .= (string) $object;
        }

        return $result;
    }

    /**
     * @param CBORObject[] $data
     */
    public static function create(array $data = []): self
    {
        return new self($data);
    }

    public function add(\Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object): self
    {
        $this->data[] = $object;
        [$this->additionalInformation, $this->length] = \Akeeba\Passwordless\CBOR\LengthCalculator::getLengthOfArray($this->data);

        return $this;
    }

    public function has(int $index): bool
    {
        return array_key_exists($index, $this->data);
    }

    public function remove(int $index): self
    {
        if (! $this->has($index)) {
            return $this;
        }
        unset($this->data[$index]);
        $this->data = array_values($this->data);
        [$this->additionalInformation, $this->length] = \Akeeba\Passwordless\CBOR\LengthCalculator::getLengthOfArray($this->data);

        return $this;
    }

    public function get(int $index): \Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject
    {
        if (! $this->has($index)) {
            throw new InvalidArgumentException('Index not found.');
        }

        return $this->data[$index];
    }

    public function set(int $index, \Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object): self
    {
        if (! $this->has($index)) {
            throw new InvalidArgumentException('Index not found.');
        }

        $this->data[$index] = $object;
        [$this->additionalInformation, $this->length] = \Akeeba\Passwordless\CBOR\LengthCalculator::getLengthOfArray($this->data);

        return $this;
    }

    /**
     * @return array<int, mixed>
     */
    public function normalize(): array
    {
        return array_map(static function (\Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object) {
            return $object instanceof \Akeeba\Passwordless\CBOR\Normalizable ? $object->normalize() : $object;
        }, $this->data);
    }

    /**
     * @deprecated The method will be removed on v3.0. Please rely on the CBOR\Normalizable interface
     *
     * @return array<int|string, mixed>
     */
    public function getNormalizedData(bool $ignoreTags = false): array
    {
        return array_map(static function (\Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject $object) use ($ignoreTags) {
            return $object->getNormalizedData($ignoreTags);
        }, $this->data);
    }

    public function count(): int
    {
        return count($this->data);
    }

    /**
     * @return Iterator<int, CBORObject>
     */
    public function getIterator(): Iterator
    {
        return new ArrayIterator($this->data);
    }

    public function offsetExists($offset): bool
    {
        return $this->has($offset);
    }

    public function offsetGet($offset): \Akeeba\Passwordless\CBOR\Akeeba\Passwordless\CBORObject
    {
        return $this->get($offset);
    }

    public function offsetSet($offset, $value): void
    {
        if ($offset === null) {
            $this->add($value);

            return;
        }

        $this->set($offset, $value);
    }

    public function offsetUnset($offset): void
    {
        $this->remove($offset);
    }
}
