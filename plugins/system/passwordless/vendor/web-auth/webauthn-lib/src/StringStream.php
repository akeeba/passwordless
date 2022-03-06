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

namespace Akeeba\Passwordless\Webauthn;

use Akeeba\Passwordless\Assert\Assertion;
use Akeeba\Passwordless\CBOR\Stream;
use function Akeeba\Passwordless\Safe\fclose;
use function Akeeba\Passwordless\Safe\fopen;
use function Akeeba\Passwordless\Safe\fread;
use function Akeeba\Passwordless\Safe\fwrite;
use function Akeeba\Passwordless\Safe\rewind;
use function Akeeba\Passwordless\Safe\sprintf;

final class StringStream implements \Akeeba\Passwordless\CBOR\Stream
{
    /**
     * @var resource
     */
    private $data;

    /**
     * @var int
     */
    private $length;

    /**
     * @var int
     */
    private $totalRead = 0;

    public function __construct(string $data)
    {
        $this->length = mb_strlen($data, '8bit');
        $resource = \Akeeba\Passwordless\Safe\fopen('php://memory', 'rb+');
        \Akeeba\Passwordless\Safe\fwrite($resource, $data);
        \Akeeba\Passwordless\Safe\rewind($resource);
        $this->data = $resource;
    }

    public function read(int $length): string
    {
        if (0 === $length) {
            return '';
        }
        $read = \Akeeba\Passwordless\Safe\fread($this->data, $length);
        $bytesRead = mb_strlen($read, '8bit');
        \Akeeba\Passwordless\Assert\Assertion::length($read, $length, \Akeeba\Passwordless\Safe\sprintf('Out of range. Expected: %d, read: %d.', $length, $bytesRead), null, '8bit');
        $this->totalRead += $bytesRead;

        return $read;
    }

    public function close(): void
    {
        \Akeeba\Passwordless\Safe\fclose($this->data);
    }

    public function isEOF(): bool
    {
        return $this->totalRead === $this->length;
    }
}
