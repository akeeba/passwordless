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

namespace Akeeba\Passwordless\Ramsey\Uuid\Generator;

use Akeeba\Passwordless\Ramsey\Uuid\Exception\NameException;
use Akeeba\Passwordless\Ramsey\Uuid\UuidInterface;
use ValueError;

use function hash;

/**
 * DefaultNameGenerator generates strings of binary data based on a namespace,
 * name, and hashing algorithm
 */
class DefaultNameGenerator implements \Akeeba\Passwordless\Ramsey\Uuid\Generator\NameGeneratorInterface
{
    /** @psalm-pure */
    public function generate(\Akeeba\Passwordless\Ramsey\Uuid\UuidInterface $ns, string $name, string $hashAlgorithm): string
    {
        try {
            /** @var string|bool $bytes */
            $bytes = @hash($hashAlgorithm, $ns->getBytes() . $name, true);
        } catch (ValueError $e) {
            $bytes = false; // keep same behavior than PHP 7
        }

        if ($bytes === false) {
            throw new \Akeeba\Passwordless\Ramsey\Uuid\Exception\NameException(sprintf(
                'Unable to hash namespace and name with algorithm \'%s\'',
                $hashAlgorithm
            ));
        }

        return (string) $bytes;
    }
}
