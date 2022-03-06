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

namespace Akeeba\Passwordless\Ramsey\Uuid\Codec;

use Akeeba\Passwordless\Ramsey\Uuid\Builder\UuidBuilderInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Exception\InvalidArgumentException;
use Akeeba\Passwordless\Ramsey\Uuid\Exception\InvalidUuidStringException;
use Akeeba\Passwordless\Ramsey\Uuid\Rfc4122\FieldsInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Uuid;
use Akeeba\Passwordless\Ramsey\Uuid\UuidInterface;

use function hex2bin;
use function implode;
use function str_replace;
use function strlen;
use function substr;

/**
 * StringCodec encodes and decodes RFC 4122 UUIDs
 *
 * @link http://tools.ietf.org/html/rfc4122
 *
 * @psalm-immutable
 */
class StringCodec implements \Akeeba\Passwordless\Ramsey\Uuid\Codec\CodecInterface
{
    /**
     * @var UuidBuilderInterface
     */
    private $builder;

    /**
     * Constructs a StringCodec
     *
     * @param UuidBuilderInterface $builder The builder to use when encoding UUIDs
     */
    public function __construct(\Akeeba\Passwordless\Ramsey\Uuid\Builder\UuidBuilderInterface $builder)
    {
        $this->builder = $builder;
    }

    public function encode(\Akeeba\Passwordless\Ramsey\Uuid\UuidInterface $uuid): string
    {
        /** @var FieldsInterface $fields */
        $fields = $uuid->getFields();

        return $fields->getTimeLow()->toString()
            . '-'
            . $fields->getTimeMid()->toString()
            . '-'
            . $fields->getTimeHiAndVersion()->toString()
            . '-'
            . $fields->getClockSeqHiAndReserved()->toString()
            . $fields->getClockSeqLow()->toString()
            . '-'
            . $fields->getNode()->toString();
    }

    /**
     * @psalm-return non-empty-string
     * @psalm-suppress MoreSpecificReturnType we know that the retrieved `string` is never empty
     * @psalm-suppress LessSpecificReturnStatement we know that the retrieved `string` is never empty
     */
    public function encodeBinary(\Akeeba\Passwordless\Ramsey\Uuid\UuidInterface $uuid): string
    {
        /** @phpstan-ignore-next-line PHPStan complains that this is not a non-empty-string. */
        return $uuid->getFields()->getBytes();
    }

    /**
     * @throws InvalidUuidStringException
     *
     * @inheritDoc
     */
    public function decode(string $encodedUuid): \Akeeba\Passwordless\Ramsey\Uuid\UuidInterface
    {
        return $this->builder->build($this, $this->getBytes($encodedUuid));
    }

    public function decodeBytes(string $bytes): \Akeeba\Passwordless\Ramsey\Uuid\UuidInterface
    {
        if (strlen($bytes) !== 16) {
            throw new \Akeeba\Passwordless\Ramsey\Uuid\Exception\InvalidArgumentException(
                '$bytes string should contain 16 characters.'
            );
        }

        return $this->builder->build($this, $bytes);
    }

    /**
     * Returns the UUID builder
     */
    protected function getBuilder(): \Akeeba\Passwordless\Ramsey\Uuid\Builder\UuidBuilderInterface
    {
        return $this->builder;
    }

    /**
     * Returns a byte string of the UUID
     */
    protected function getBytes(string $encodedUuid): string
    {
        $parsedUuid = str_replace(
            ['urn:', 'uuid:', 'URN:', 'UUID:', '{', '}', '-'],
            '',
            $encodedUuid
        );

        $components = [
            substr($parsedUuid, 0, 8),
            substr($parsedUuid, 8, 4),
            substr($parsedUuid, 12, 4),
            substr($parsedUuid, 16, 4),
            substr($parsedUuid, 20),
        ];

        if (!\Akeeba\Passwordless\Ramsey\Uuid\Uuid::isValid(implode('-', $components))) {
            throw new \Akeeba\Passwordless\Ramsey\Uuid\Exception\InvalidUuidStringException(
                'Invalid UUID string: ' . $encodedUuid
            );
        }

        return (string) hex2bin($parsedUuid);
    }
}
