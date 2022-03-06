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

use Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObject;

/**
 * @see https://www.w3.org/TR/webauthn/#authenticatorattestationresponse
 */
class AuthenticatorAttestationResponse extends \Akeeba\Passwordless\Webauthn\AuthenticatorResponse
{
    /**
     * @var AttestationObject
     */
    private $attestationObject;

    public function __construct(\Akeeba\Passwordless\Webauthn\CollectedClientData $clientDataJSON, \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObject $attestationObject)
    {
        parent::__construct($clientDataJSON);
        $this->attestationObject = $attestationObject;
    }

    public function getAttestationObject(): \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObject
    {
        return $this->attestationObject;
    }
}
