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

use function array_key_exists;
use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use function in_array;
use InvalidArgumentException;
use function Akeeba\Passwordless\Safe\class_implements;
use function Akeeba\Passwordless\Safe\sprintf;

abstract class TrustPathLoader
{
    /**
     * @param mixed[] $data
     */
    public static function loadTrustPath(array $data): \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($data, 'type', 'The trust path type is missing');
        $type = $data['type'];
        $oldTypes = self::oldTrustPathTypes();
        switch (true) {
            case array_key_exists($type, $oldTypes):
                return $oldTypes[$type]::createFromArray($data);
            case class_exists($type):
                $implements = \Akeeba\Passwordless\Safe\class_implements($type);
                if (in_array(\Akeeba\Passwordless\Webauthn\TrustPath\TrustPath::class, $implements, true)) {
                    return $type::createFromArray($data);
                }
                // no break
            default:
                throw new InvalidArgumentException(\Akeeba\Passwordless\Safe\sprintf('The trust path type "%s" is not supported', $data['type']));
        }
    }

    /**
     * @return string[]
     */
    private static function oldTrustPathTypes(): array
    {
        return [
            'empty' => \Akeeba\Passwordless\Webauthn\TrustPath\EmptyTrustPath::class,
            'ecdaa_key_id' => \Akeeba\Passwordless\Webauthn\TrustPath\EcdaaKeyIdTrustPath::class,
            'x5c' => \Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath::class,
        ];
    }
}
