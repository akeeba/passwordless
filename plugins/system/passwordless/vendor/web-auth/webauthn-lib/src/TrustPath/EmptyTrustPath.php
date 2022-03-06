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

final class EmptyTrustPath implements \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath
{
    /**
     * @return string[]
     */
    public function jsonSerialize(): array
    {
        return [
            'type' => self::class,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromArray(array $data): \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath
    {
        return new \Akeeba\Passwordless\Webauthn\TrustPath\EmptyTrustPath();
    }
}
