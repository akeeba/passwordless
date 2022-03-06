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

class PublicKeyCredentialRpEntity extends \Akeeba\Passwordless\Webauthn\PublicKeyCredentialEntity
{
    /**
     * @var string|null
     */
    protected $id;

    public function __construct(string $name, ?string $id = null, ?string $icon = null)
    {
        parent::__construct($name, $icon);
        $this->id = $id;
    }

    public function getId(): ?string
    {
        return $this->id;
    }

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): self
    {
        \Akeeba\Passwordless\Assert\Assertion::keyExists($json, 'name', 'Invalid input. "name" is missing.');

        return new self(
            $json['name'],
            $json['id'] ?? null,
            $json['icon'] ?? null
        );
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        $json = parent::jsonSerialize();
        if (null !== $this->id) {
            $json['id'] = $this->id;
        }

        return $json;
    }
}
