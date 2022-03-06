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

use Akeeba\Passwordless\Assert\Assertion;
use function count;
use Akeeba\Passwordless\Webauthn\AuthenticatorData;
use Akeeba\Passwordless\Webauthn\TrustPath\EmptyTrustPath;

final class NoneAttestationStatementSupport implements \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupport
{
    public function name(): string
    {
        return 'none';
    }

    /**
     * @param mixed[] $attestation
     */
    public function load(array $attestation): \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement
    {
        \Akeeba\Passwordless\Assert\Assertion::noContent($attestation['attStmt'], 'Invalid attestation object');

        return \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement::createNone($attestation['fmt'], $attestation['attStmt'], new \Akeeba\Passwordless\Webauthn\TrustPath\EmptyTrustPath());
    }

    public function isValid(string $clientDataJSONHash, \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement $attestationStatement, \Akeeba\Passwordless\Webauthn\AuthenticatorData $authenticatorData): bool
    {
        return 0 === count($attestationStatement->getAttStmt());
    }
}
