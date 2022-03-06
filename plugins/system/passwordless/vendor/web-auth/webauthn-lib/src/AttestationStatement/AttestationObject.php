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

use Akeeba\Passwordless\Webauthn\AuthenticatorData;
use Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement;

class AttestationObject
{
    /**
     * @var string
     */
    private $rawAttestationObject;
    /**
     * @var AttestationStatement
     */
    private $attStmt;
    /**
     * @var AuthenticatorData
     */
    private $authData;

    /**
     * @var MetadataStatement|null
     */
    private $metadataStatement;

    public function __construct(string $rawAttestationObject, \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement $attStmt, \Akeeba\Passwordless\Webauthn\AuthenticatorData $authData, ?\Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement $metadataStatement = null)
    {
        if (null !== $metadataStatement) {
            @trigger_error('The argument "metadataStatement" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setMetadataStatement".', E_USER_DEPRECATED);
        }
        $this->rawAttestationObject = $rawAttestationObject;
        $this->attStmt = $attStmt;
        $this->authData = $authData;
        $this->metadataStatement = $metadataStatement;
    }

    public function getRawAttestationObject(): string
    {
        return $this->rawAttestationObject;
    }

    public function getAttStmt(): \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement
    {
        return $this->attStmt;
    }

    public function setAttStmt(\Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement $attStmt): void
    {
        $this->attStmt = $attStmt;
    }

    public function getAuthData(): \Akeeba\Passwordless\Webauthn\AuthenticatorData
    {
        return $this->authData;
    }

    public function getMetadataStatement(): ?\Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement
    {
        return $this->metadataStatement;
    }

    public function setMetadataStatement(\Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement $metadataStatement): self
    {
        $this->metadataStatement = $metadataStatement;

        return $this;
    }
}
