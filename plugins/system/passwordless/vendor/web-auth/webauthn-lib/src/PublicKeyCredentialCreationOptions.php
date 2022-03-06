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

use Akeeba\Passwordless\Assert\Assertion;
use Akeeba\Passwordless\Base64Url\Base64Url;
use function count;
use function Akeeba\Passwordless\Safe\json_decode;
use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;

class PublicKeyCredentialCreationOptions extends \Akeeba\Passwordless\Webauthn\PublicKeyCredentialOptions
{
    public const ATTESTATION_CONVEYANCE_PREFERENCE_NONE = 'none';
    public const ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT = 'indirect';
    public const ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT = 'direct';
    public const ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE = 'enterprise';

    /**
     * @var PublicKeyCredentialRpEntity
     */
    private $rp;

    /**
     * @var PublicKeyCredentialUserEntity
     */
    private $user;

    /**
     * @var PublicKeyCredentialParameters[]
     */
    private $pubKeyCredParams = [];

    /**
     * @var PublicKeyCredentialDescriptor[]
     */
    private $excludeCredentials = [];

    /**
     * @var AuthenticatorSelectionCriteria
     */
    private $authenticatorSelection;

    /**
     * @var string
     */
    private $attestation;

    /**
     * @param PublicKeyCredentialParameters[] $pubKeyCredParams
     * @param PublicKeyCredentialDescriptor[] $excludeCredentials
     */
    public function __construct(\Akeeba\Passwordless\Webauthn\PublicKeyCredentialRpEntity $rp, \Akeeba\Passwordless\Webauthn\PublicKeyCredentialUserEntity $user, string $challenge, array $pubKeyCredParams, ?int $timeout = null, array $excludeCredentials = [], ?\Akeeba\Passwordless\Webauthn\AuthenticatorSelectionCriteria $authenticatorSelection = null, ?string $attestation = null, ?\Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs $extensions = null)
    {
        if (0 !== count($excludeCredentials)) {
            @trigger_error('The argument "excludeCredentials" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "excludeCredentials" or "excludeCredential".', E_USER_DEPRECATED);
        }
        if (null !== $authenticatorSelection) {
            @trigger_error('The argument "authenticatorSelection" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setAuthenticatorSelection".', E_USER_DEPRECATED);
        }
        if (null !== $attestation) {
            @trigger_error('The argument "attestation" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setAttestation".', E_USER_DEPRECATED);
        }
        parent::__construct($challenge, $timeout, $extensions);
        $this->rp = $rp;
        $this->user = $user;
        $this->pubKeyCredParams = $pubKeyCredParams;
        $this->authenticatorSelection = $authenticatorSelection ?? new \Akeeba\Passwordless\Webauthn\AuthenticatorSelectionCriteria();
        $this->attestation = $attestation ?? self::ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
        $this->excludeCredentials($excludeCredentials)
        ;
    }

    /**
     * @param PublicKeyCredentialParameters[] $pubKeyCredParams
     */
    public static function create(\Akeeba\Passwordless\Webauthn\PublicKeyCredentialRpEntity $rp, \Akeeba\Passwordless\Webauthn\PublicKeyCredentialUserEntity $user, string $challenge, array $pubKeyCredParams): self
    {
        return new self($rp, $user, $challenge, $pubKeyCredParams);
    }

    public function addPubKeyCredParam(\Akeeba\Passwordless\Webauthn\PublicKeyCredentialParameters $pubKeyCredParam): self
    {
        $this->pubKeyCredParams[] = $pubKeyCredParam;

        return $this;
    }

    /**
     * @param PublicKeyCredentialParameters[] $pubKeyCredParams
     */
    public function addPubKeyCredParams(array $pubKeyCredParams): self
    {
        foreach ($pubKeyCredParams as $pubKeyCredParam) {
            $this->addPubKeyCredParam($pubKeyCredParam);
        }

        return $this;
    }

    public function excludeCredential(\Akeeba\Passwordless\Webauthn\PublicKeyCredentialDescriptor $excludeCredential): self
    {
        $this->excludeCredentials[] = $excludeCredential;

        return $this;
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $excludeCredentials
     */
    public function excludeCredentials(array $excludeCredentials): self
    {
        foreach ($excludeCredentials as $excludeCredential) {
            $this->excludeCredential($excludeCredential);
        }

        return $this;
    }

    public function setAuthenticatorSelection(\Akeeba\Passwordless\Webauthn\AuthenticatorSelectionCriteria $authenticatorSelection): self
    {
        $this->authenticatorSelection = $authenticatorSelection;

        return $this;
    }

    public function setAttestation(string $attestation): self
    {
        \Akeeba\Passwordless\Assert\Assertion::inArray($attestation, [
            self::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            self::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            self::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT,
            self::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE,
        ], 'Invalid attestation conveyance mode');
        $this->attestation = $attestation;

        return $this;
    }

    public function getRp(): \Akeeba\Passwordless\Webauthn\PublicKeyCredentialRpEntity
    {
        return $this->rp;
    }

    public function getUser(): \Akeeba\Passwordless\Webauthn\PublicKeyCredentialUserEntity
    {
        return $this->user;
    }

    /**
     * @return PublicKeyCredentialParameters[]
     */
    public function getPubKeyCredParams(): array
    {
        return $this->pubKeyCredParams;
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    public function getExcludeCredentials(): array
    {
        return $this->excludeCredentials;
    }

    public function getAuthenticatorSelection(): \Akeeba\Passwordless\Webauthn\AuthenticatorSelectionCriteria
    {
        return $this->authenticatorSelection;
    }

    public function getAttestation(): string
    {
        return $this->attestation;
    }

    public static function createFromString(string $data): \Akeeba\Passwordless\Webauthn\PublicKeyCredentialOptions
    {
        $data = \Akeeba\Passwordless\Safe\json_decode($data, true);
        \Akeeba\Passwordless\Assert\Assertion::isArray($data, 'Invalid data');

        return self::createFromArray($data);
    }

    public static function createFromArray(array $json): \Akeeba\Passwordless\Webauthn\PublicKeyCredentialOptions
    {
        \Akeeba\Passwordless\Assert\Assertion::keyExists($json, 'rp', 'Invalid input. "rp" is missing.');
        \Akeeba\Passwordless\Assert\Assertion::keyExists($json, 'pubKeyCredParams', 'Invalid input. "pubKeyCredParams" is missing.');
        \Akeeba\Passwordless\Assert\Assertion::isArray($json['pubKeyCredParams'], 'Invalid input. "pubKeyCredParams" is not an array.');
        \Akeeba\Passwordless\Assert\Assertion::keyExists($json, 'challenge', 'Invalid input. "challenge" is missing.');
        \Akeeba\Passwordless\Assert\Assertion::keyExists($json, 'attestation', 'Invalid input. "attestation" is missing.');
        \Akeeba\Passwordless\Assert\Assertion::keyExists($json, 'user', 'Invalid input. "user" is missing.');
        \Akeeba\Passwordless\Assert\Assertion::keyExists($json, 'authenticatorSelection', 'Invalid input. "authenticatorSelection" is missing.');

        $pubKeyCredParams = [];
        foreach ($json['pubKeyCredParams'] as $pubKeyCredParam) {
            $pubKeyCredParams[] = \Akeeba\Passwordless\Webauthn\PublicKeyCredentialParameters::createFromArray($pubKeyCredParam);
        }
        $excludeCredentials = [];
        if (isset($json['excludeCredentials'])) {
            foreach ($json['excludeCredentials'] as $excludeCredential) {
                $excludeCredentials[] = \Akeeba\Passwordless\Webauthn\PublicKeyCredentialDescriptor::createFromArray($excludeCredential);
            }
        }

        return self::create(
                \Akeeba\Passwordless\Webauthn\PublicKeyCredentialRpEntity::createFromArray($json['rp']),
                \Akeeba\Passwordless\Webauthn\PublicKeyCredentialUserEntity::createFromArray($json['user']),
                Base64Url::decode($json['challenge']),
                $pubKeyCredParams
            )
            ->excludeCredentials($excludeCredentials)
            ->setAuthenticatorSelection(\Akeeba\Passwordless\Webauthn\AuthenticatorSelectionCriteria::createFromArray($json['authenticatorSelection']))
            ->setAttestation($json['attestation'])
            ->setTimeout($json['timeout'] ?? null)
            ->setExtensions(isset($json['extensions']) ? \Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs::createFromArray($json['extensions']) : new \Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs())
        ;
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        $json = [
            'rp' => $this->rp->jsonSerialize(),
            'pubKeyCredParams' => array_map(static function (\Akeeba\Passwordless\Webauthn\PublicKeyCredentialParameters $object): array {
                return $object->jsonSerialize();
            }, $this->pubKeyCredParams),
            'challenge' => Base64Url::encode($this->challenge),
            'attestation' => $this->attestation,
            'user' => $this->user->jsonSerialize(),
            'authenticatorSelection' => $this->authenticatorSelection->jsonSerialize(),
        ];

        if (0 !== count($this->excludeCredentials)) {
            $json['excludeCredentials'] = array_map(static function (\Akeeba\Passwordless\Webauthn\PublicKeyCredentialDescriptor $object): array {
                return $object->jsonSerialize();
            }, $this->excludeCredentials);
        }

        if (0 !== $this->extensions->count()) {
            $json['extensions'] = $this->extensions;
        }

        if (null !== $this->timeout) {
            $json['timeout'] = $this->timeout;
        }

        return $json;
    }
}
