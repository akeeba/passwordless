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

final class CertificateTrustPath implements \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath
{
    /**
     * @var string[]
     */
    private $certificates;

    /**
     * @param string[] $certificates
     */
    public function __construct(array $certificates)
    {
        $this->certificates = $certificates;
    }

    /**
     * @return string[]
     */
    public function getCertificates(): array
    {
        return $this->certificates;
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromArray(array $data): \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath
    {
        \Akeeba\Passwordless\Assert\Assertion::keyExists($data, 'x5c', 'The trust path type is invalid');

        return new \Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath($data['x5c']);
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        return [
            'type' => self::class,
            'x5c' => $this->certificates,
        ];
    }
}
