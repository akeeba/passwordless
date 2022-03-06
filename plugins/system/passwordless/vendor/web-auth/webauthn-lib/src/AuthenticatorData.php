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

use function ord;
use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;

/**
 * @see https://www.w3.org/TR/webauthn/#sec-authenticator-data
 */
class AuthenticatorData
{
    private const FLAG_UP = 0b00000001;
    private const FLAG_RFU1 = 0b00000010;
    private const FLAG_UV = 0b00000100;
    private const FLAG_RFU2 = 0b00111000;
    private const FLAG_AT = 0b01000000;
    private const FLAG_ED = 0b10000000;
    /**
     * @var string
     */
    protected $authData;

    /**
     * @var string
     */
    protected $rpIdHash;

    /**
     * @var string
     */
    protected $flags;

    /**
     * @var int
     */
    protected $signCount;

    /**
     * @var AttestedCredentialData|null
     */
    protected $attestedCredentialData;

    /**
     * @var AuthenticationExtensionsClientOutputs|null
     */
    protected $extensions;

    public function __construct(string $authData, string $rpIdHash, string $flags, int $signCount, ?\Akeeba\Passwordless\Webauthn\AttestedCredentialData $attestedCredentialData, ?\Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs $extensions)
    {
        $this->rpIdHash = $rpIdHash;
        $this->flags = $flags;
        $this->signCount = $signCount;
        $this->attestedCredentialData = $attestedCredentialData;
        $this->extensions = $extensions;
        $this->authData = $authData;
    }

    public function getAuthData(): string
    {
        return $this->authData;
    }

    public function getRpIdHash(): string
    {
        return $this->rpIdHash;
    }

    public function isUserPresent(): bool
    {
        return 0 !== (ord($this->flags) & self::FLAG_UP) ? true : false;
    }

    public function isUserVerified(): bool
    {
        return 0 !== (ord($this->flags) & self::FLAG_UV) ? true : false;
    }

    public function hasAttestedCredentialData(): bool
    {
        return 0 !== (ord($this->flags) & self::FLAG_AT) ? true : false;
    }

    public function hasExtensions(): bool
    {
        return 0 !== (ord($this->flags) & self::FLAG_ED) ? true : false;
    }

    public function getReservedForFutureUse1(): int
    {
        return ord($this->flags) & self::FLAG_RFU1;
    }

    public function getReservedForFutureUse2(): int
    {
        return ord($this->flags) & self::FLAG_RFU2;
    }

    public function getSignCount(): int
    {
        return $this->signCount;
    }

    public function getAttestedCredentialData(): ?\Akeeba\Passwordless\Webauthn\AttestedCredentialData
    {
        return $this->attestedCredentialData;
    }

    public function getExtensions(): ?\Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs
    {
        return null !== $this->extensions && $this->hasExtensions() ? $this->extensions : null;
    }
}
