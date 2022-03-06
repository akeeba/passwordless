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

namespace Akeeba\Passwordless\Webauthn\TokenBinding;

use function array_key_exists;
use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use Akeeba\Passwordless\Base64Url\Akeeba\Passwordless\Base64Url;
use function Akeeba\Passwordless\Safe\sprintf;

class TokenBinding
{
    public const TOKEN_BINDING_STATUS_PRESENT = 'present';
    public const TOKEN_BINDING_STATUS_SUPPORTED = 'supported';
    public const TOKEN_BINDING_STATUS_NOT_SUPPORTED = 'not-supported';

    /**
     * @var string
     */
    private $status;

    /**
     * @var string|null
     */
    private $id;

    public function __construct(string $status, ?string $id)
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::false(self::TOKEN_BINDING_STATUS_PRESENT === $status && null === $id, 'The member "id" is required when status is "present"');
        $this->status = $status;
        $this->id = $id;
    }

    /**
     * @param mixed[] $json
     */
    public static function createFormArray(array $json): self
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($json, 'status', 'The member "status" is required');
        $status = $json['status'];
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::inArray(
            $status,
            self::getSupportedStatus(),
            \Akeeba\Passwordless\Safe\sprintf('The member "status" is invalid. Supported values are: %s', implode(', ', self::getSupportedStatus()))
        );
        $id = array_key_exists('id', $json) ? \Akeeba\Passwordless\Base64Url\Akeeba\Passwordless\Base64Url::decode($json['id']) : null;

        return new self($status, $id);
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function getId(): ?string
    {
        return $this->id;
    }

    /**
     * @return string[]
     */
    private static function getSupportedStatus(): array
    {
        return [
            self::TOKEN_BINDING_STATUS_PRESENT,
            self::TOKEN_BINDING_STATUS_SUPPORTED,
            self::TOKEN_BINDING_STATUS_NOT_SUPPORTED,
        ];
    }
}
