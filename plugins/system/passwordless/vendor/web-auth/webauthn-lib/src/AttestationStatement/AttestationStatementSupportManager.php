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

namespace Akeeba\Passwordless\Webauthn\AttestationStatement;

use function array_key_exists;
use Akeeba\Passwordless\Assert\Assertion;
use function Akeeba\Passwordless\Safe\sprintf;

class AttestationStatementSupportManager
{
    /**
     * @var AttestationStatementSupport[]
     */
    private $attestationStatementSupports = [];

    public function add(\Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupport $attestationStatementSupport): void
    {
        $this->attestationStatementSupports[$attestationStatementSupport->name()] = $attestationStatementSupport;
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->attestationStatementSupports);
    }

    public function get(string $name): \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupport
    {
        \Akeeba\Passwordless\Assert\Assertion::true($this->has($name), \Akeeba\Passwordless\Safe\sprintf('The attestation statement format "%s" is not supported.', $name));

        return $this->attestationStatementSupports[$name];
    }
}
