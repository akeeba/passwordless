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

namespace Akeeba\Passwordless\Webauthn\TrustPath;

use Akeeba\Passwordless\Assert\Assertion;

final class EcdaaKeyIdTrustPath implements \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath
{
    /**
     * @var string
     */
    private $ecdaaKeyId;

    public function __construct(string $ecdaaKeyId)
    {
        $this->ecdaaKeyId = $ecdaaKeyId;
    }

    public function getEcdaaKeyId(): string
    {
        return $this->ecdaaKeyId;
    }

    /**
     * @return string[]
     */
    public function jsonSerialize(): array
    {
        return [
            'type' => self::class,
            'ecdaaKeyId' => $this->ecdaaKeyId,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromArray(array $data): \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath
    {
        \Akeeba\Passwordless\Assert\Assertion::keyExists($data, 'ecdaaKeyId', 'The trust path type is invalid');

        return new \Akeeba\Passwordless\Webauthn\TrustPath\EcdaaKeyIdTrustPath($data['ecdaaKeyId']);
    }
}
