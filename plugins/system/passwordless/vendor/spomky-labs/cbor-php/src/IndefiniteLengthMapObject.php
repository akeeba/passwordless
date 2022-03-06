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
 * @phpstan-implements IteratorAggregate<int, MapItem>
 * @final
 */
class IndefiniteLengthMapObject extends \Akeeba\Passwordless\CBOR\AbstractCBORObject implements Countable, IteratorAggregate, \Akeeba\Passwordless\CBOR\Normalizable, ArrayAccess
{
    private const MAJOR_TYPE = self::MAJOR_TYPE_MAP;

    private const ADDITIONAL_INFORMATION = self::LENGTH_INDEFINITE;

    /**
     * @var MapItem[]
     */
    private $data = [];

    public function __construct()
    {
        parent::__construct(self::MAJOR_TYPE, self::ADDITIONAL_INFORMATION);
    }

    public function __toString(): string
    {
        $result = parent::__toString();
        foreach ($this->data as $object) {
            $result .= (string) $object->getKey();
            $result .= (string) $object->getValue();
        }

        return $result . "\xFF";
    }

    public static function create(): self
    {
        return new self();
    }

    /**
     * @deprecated The method will be removed on v3.0. Please use "add" instead
     */
    public function append(\Akeeba\Passwordless\CBOR\CBORObject $key, \Akeeba\Passwordless\CBOR\CBORObject $value): self
    {
        return $this->add($key, $value);
    }

    public function add(\Akeeba\Passwordless\CBOR\CBORObject $key, \Akeeba\Passwordless\CBOR\CBORObject $value): self
    {
        if (! $key instanceof \Akeeba\Passwordless\CBOR\Normalizable) {
            throw new InvalidArgumentException('Invalid key. Shall be normalizable');
        }
        $this->data[$key->normalize()] = \Akeeba\Passwordless\CBOR\MapItem::create($key, $value);

        return $this;
    }

    /**
     * @param int|string $key
     */
    public function has($key): bool
    {
        return array_key_exists($key, $this->data);
    }

    /**
     * @param int|string $index
     */
    public function remove($index): self
    {
        if (! $this->has($index)) {
            return $this;
        }
        unset($this->data[$index]);
        $this->data = array_values($this->data);

        return $this;
    }

    /**
     * @param int|string $index
     */
    public function get($index): \Akeeba\Passwordless\CBOR\CBORObject
    {
        if (! $this->has($index)) {
            throw new InvalidArgumentException('Index not found.');
        }

        return $this->data[$index]->getValue();
    }

    public function set(\Akeeba\Passwordless\CBOR\MapItem $object): self
    {
        $key = $object->getKey();
        if (! $key instanceof \Akeeba\Passwordless\CBOR\Normalizable) {
            throw new InvalidArgumentException('Invalid key. Shall be normalizable');
        }

        $this->data[$key->normalize()] = $object;

        return $this;
    }

    /**
     * @deprecated The method will be removed on v3.0. No replacement
     */
    public function count(): int
    {
        return count($this->data);
    }

    /**
     * @return Iterator<int, MapItem>
     */
    public function getIterator(): Iterator
    {
        return new ArrayIterator($this->data);
    }

    /**
     * @return mixed[]
     */
    public function normalize(): array
    {
        return array_reduce($this->data, static function (array $carry, \Akeeba\Passwordless\CBOR\MapItem $item): array {
            $key = $item->getKey();
            if (! $key instanceof \Akeeba\Passwordless\CBOR\Normalizable) {
                throw new InvalidArgumentException('Invalid key. Shall be normalizable');
            }
            $valueObject = $item->getValue();
            $carry[$key->normalize()] = $valueObject instanceof \Akeeba\Passwordless\CBOR\Normalizable ? $valueObject->normalize() : $valueObject;

            return $carry;
        }, []);
    }

    /**
     * @deprecated The method will be removed on v3.0. Please rely on the CBOR\Normalizable interface
     *
     * @return mixed[]
     */
    public function getNormalizedData(bool $ignoreTags = false): array
    {
        return array_reduce($this->data, static function (array $carry, \Akeeba\Passwordless\CBOR\MapItem $item) use ($ignoreTags): array {
            $key = $item->getKey();
            $valueObject = $item->getValue();
            $carry[$key->getNormalizedData($ignoreTags)] = $valueObject->getNormalizedData($ignoreTags);

            return $carry;
        }, []);
    }

    public function offsetExists($offset): bool
    {
        return $this->has($offset);
    }

    public function offsetGet($offset): \Akeeba\Passwordless\CBOR\CBORObject
    {
        return $this->get($offset);
    }

    public function offsetSet($offset, $value): void
    {
        if (! $offset instanceof \Akeeba\Passwordless\CBOR\CBORObject) {
            throw new InvalidArgumentException('Invalid key');
        }
        if (! $value instanceof \Akeeba\Passwordless\CBOR\CBORObject) {
            throw new InvalidArgumentException('Invalid value');
        }

        $this->set(\Akeeba\Passwordless\CBOR\MapItem::create($offset, $value));
    }

    public function offsetUnset($offset): void
    {
        $this->remove($offset);
    }
}
