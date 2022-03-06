<?php

/**
 * This file is part of the ramsey/collection library
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @copyright Copyright (c) Ben Ramsey <ben@benramsey.com>
 * @license http://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace Akeeba\Passwordless\Ramsey\Collection\Map;

use Akeeba\Passwordless\Ramsey\Collection\Exception\InvalidArgumentException;
use Akeeba\Passwordless\Ramsey\Collection\Tool\TypeTrait;
use Akeeba\Passwordless\Ramsey\Collection\Tool\ValueToStringTrait;

/**
 * This class provides a basic implementation of `TypedMapInterface`, to
 * minimize the effort required to implement this interface.
 *
 * @template K
 * @template T
 * @extends AbstractMap<T>
 * @implements TypedMapInterface<T>
 */
abstract class AbstractTypedMap extends \Akeeba\Passwordless\Ramsey\Collection\Map\AbstractMap implements \Akeeba\Passwordless\Ramsey\Collection\Map\TypedMapInterface
{
    use \Akeeba\Passwordless\Ramsey\Collection\Tool\TypeTrait;
    use \Akeeba\Passwordless\Ramsey\Collection\Tool\ValueToStringTrait;

    /**
     * @param K|null $offset
     * @param T $value
     *
     * @inheritDoc
     *
     * @psalm-suppress MoreSpecificImplementedParamType
     */
    public function offsetSet($offset, $value): void
    {
        if ($offset === null) {
            throw new \Akeeba\Passwordless\Ramsey\Collection\Exception\InvalidArgumentException(
                'Map elements are key/value pairs; a key must be provided for '
                . 'value ' . var_export($value, true)
            );
        }

        if ($this->checkType($this->getKeyType(), $offset) === false) {
            throw new \Akeeba\Passwordless\Ramsey\Collection\Exception\InvalidArgumentException(
                'Key must be of type ' . $this->getKeyType() . '; key is '
                . $this->toolValueToString($offset)
            );
        }

        if ($this->checkType($this->getValueType(), $value) === false) {
            throw new \Akeeba\Passwordless\Ramsey\Collection\Exception\InvalidArgumentException(
                'Value must be of type ' . $this->getValueType() . '; value is '
                . $this->toolValueToString($value)
            );
        }

        /** @psalm-suppress MixedArgumentTypeCoercion */
        parent::offsetSet($offset, $value);
    }
}
