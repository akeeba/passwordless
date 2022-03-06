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

use function Akeeba\Passwordless\Safe\base64_decode;

/**
 * @see https://www.w3.org/TR/webauthn/#authenticatorassertionresponse
 */
class AuthenticatorAssertionResponse extends \Akeeba\Passwordless\Webauthn\AuthenticatorResponse
{
    /**
     * @var AuthenticatorData
     */
    private $authenticatorData;

    /**
     * @var string
     */
    private $signature;

    /**
     * @var string|null
     */
    private $userHandle;

    public function __construct(\Akeeba\Passwordless\Webauthn\CollectedClientData $clientDataJSON, \Akeeba\Passwordless\Webauthn\AuthenticatorData $authenticatorData, string $signature, ?string $userHandle)
    {
        parent::__construct($clientDataJSON);
        $this->authenticatorData = $authenticatorData;
        $this->signature = $signature;
        $this->userHandle = $userHandle;
    }

    public function getAuthenticatorData(): \Akeeba\Passwordless\Webauthn\AuthenticatorData
    {
        return $this->authenticatorData;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    public function getUserHandle(): ?string
    {
        if (null === $this->userHandle || '' === $this->userHandle) {
            return $this->userHandle;
        }

        return \Akeeba\Passwordless\Safe\base64_decode($this->userHandle, true);
    }
}
