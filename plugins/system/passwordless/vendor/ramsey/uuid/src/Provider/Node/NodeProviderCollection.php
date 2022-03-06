<?php

/**
 * This file is part of the ramsey/uuid library
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @copyright Copyright (c) Ben Ramsey <ben@benramsey.com>
 * @license http://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace Akeeba\Passwordless\Ramsey\Uuid\Provider\Node;

use Akeeba\Passwordless\Ramsey\Collection\AbstractCollection;
use Akeeba\Passwordless\Ramsey\Uuid\Provider\NodeProviderInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Type\Hexadecimal;

/**
 * A collection of NodeProviderInterface objects
 *
 * @extends AbstractCollection<NodeProviderInterface>
 */
class NodeProviderCollection extends \Akeeba\Passwordless\Ramsey\Collection\AbstractCollection
{
    public function getType(): string
    {
        return \Akeeba\Passwordless\Ramsey\Uuid\Provider\NodeProviderInterface::class;
    }

    /**
     * Re-constructs the object from its serialized form
     *
     * @param string $serialized The serialized PHP string to unserialize into
     *     a UuidInterface instance
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.ParameterTypeHint.MissingNativeTypeHint
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    public function unserialize($serialized): void
    {
        /** @var array<array-key, NodeProviderInterface> $data */
        $data = unserialize($serialized, [
            'allowed_classes' => [
                \Akeeba\Passwordless\Ramsey\Uuid\Type\Hexadecimal::class,
                \Akeeba\Passwordless\Ramsey\Uuid\Provider\Node\RandomNodeProvider::class,
                \Akeeba\Passwordless\Ramsey\Uuid\Provider\Node\StaticNodeProvider::class,
                \Akeeba\Passwordless\Ramsey\Uuid\Provider\Node\SystemNodeProvider::class,
            ],
        ]);

        $this->data = array_filter(
            $data,
            function ($unserialized): bool {
                return $unserialized instanceof \Akeeba\Passwordless\Ramsey\Uuid\Provider\NodeProviderInterface;
            }
        );
    }
}
