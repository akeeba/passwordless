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

namespace Akeeba\Passwordless\Webauthn\MetadataService;

use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use JsonSerializable;
use function Akeeba\Passwordless\Safe\sprintf;

class VerificationMethodDescriptor implements JsonSerializable
{
    public const USER_VERIFY_PRESENCE = 0x00000001;
    public const USER_VERIFY_FINGERPRINT = 0x00000002;
    public const USER_VERIFY_PASSCODE = 0x00000004;
    public const USER_VERIFY_VOICEPRINT = 0x00000008;
    public const USER_VERIFY_FACEPRINT = 0x00000010;
    public const USER_VERIFY_LOCATION = 0x00000020;
    public const USER_VERIFY_EYEPRINT = 0x00000040;
    public const USER_VERIFY_PATTERN = 0x00000080;
    public const USER_VERIFY_HANDPRINT = 0x00000100;
    public const USER_VERIFY_NONE = 0x00000200;
    public const USER_VERIFY_ALL = 0x00000400;

    /**
     * @var int
     */
    private $userVerification;

    /**
     * @var CodeAccuracyDescriptor|null
     */
    private $caDesc;

    /**
     * @var BiometricAccuracyDescriptor|null
     */
    private $baDesc;

    /**
     * @var PatternAccuracyDescriptor|null
     */
    private $paDesc;

    public function __construct(int $userVerification, ?\Akeeba\Passwordless\Webauthn\MetadataService\CodeAccuracyDescriptor $caDesc = null, ?\Akeeba\Passwordless\Webauthn\MetadataService\BiometricAccuracyDescriptor $baDesc = null, ?\Akeeba\Passwordless\Webauthn\MetadataService\PatternAccuracyDescriptor $paDesc = null)
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::greaterOrEqualThan($userVerification, 0, \Akeeba\Passwordless\Webauthn\MetadataService\Utils::logicException('The parameter "userVerification" is invalid'));
        $this->userVerification = $userVerification;
        $this->caDesc = $caDesc;
        $this->baDesc = $baDesc;
        $this->paDesc = $paDesc;
    }

    public function getUserVerification(): int
    {
        return $this->userVerification;
    }

    public function userPresence(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_PRESENCE);
    }

    public function fingerprint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_FINGERPRINT);
    }

    public function passcode(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_PASSCODE);
    }

    public function voicePrint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_VOICEPRINT);
    }

    public function facePrint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_FACEPRINT);
    }

    public function location(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_LOCATION);
    }

    public function eyePrint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_EYEPRINT);
    }

    public function pattern(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_PATTERN);
    }

    public function handprint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_HANDPRINT);
    }

    public function none(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_NONE);
    }

    public function all(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_ALL);
    }

    public function getCaDesc(): ?\Akeeba\Passwordless\Webauthn\MetadataService\CodeAccuracyDescriptor
    {
        return $this->caDesc;
    }

    public function getBaDesc(): ?\Akeeba\Passwordless\Webauthn\MetadataService\BiometricAccuracyDescriptor
    {
        return $this->baDesc;
    }

    public function getPaDesc(): ?\Akeeba\Passwordless\Webauthn\MetadataService\PatternAccuracyDescriptor
    {
        return $this->paDesc;
    }

    public static function createFromArray(array $data): self
    {
        $data = \Akeeba\Passwordless\Webauthn\MetadataService\Utils::filterNullValues($data);
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($data, 'userVerification', \Akeeba\Passwordless\Webauthn\MetadataService\Utils::logicException('The parameter "userVerification" is missing'));
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::integer($data['userVerification'], \Akeeba\Passwordless\Webauthn\MetadataService\Utils::logicException('The parameter "userVerification" is invalid'));
        foreach (['caDesc', 'baDesc', 'paDesc'] as $key) {
            if (isset($data[$key])) {
                \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isArray($data[$key], \Akeeba\Passwordless\Webauthn\MetadataService\Utils::logicException(\Akeeba\Passwordless\Safe\sprintf('Invalid parameter "%s"', $key)));
            }
        }

        return new self(
            $data['userVerification'],
            isset($data['caDesc']) ? \Akeeba\Passwordless\Webauthn\MetadataService\CodeAccuracyDescriptor::createFromArray($data['caDesc']) : null,
            isset($data['baDesc']) ? \Akeeba\Passwordless\Webauthn\MetadataService\BiometricAccuracyDescriptor::createFromArray($data['baDesc']) : null,
            isset($data['paDesc']) ? \Akeeba\Passwordless\Webauthn\MetadataService\PatternAccuracyDescriptor::createFromArray($data['paDesc']) : null
        );
    }

    public function jsonSerialize(): array
    {
        $data = [
            'userVerification' => $this->userVerification,
            'caDesc' => null === $this->caDesc ? null : $this->caDesc->jsonSerialize(),
            'baDesc' => null === $this->baDesc ? null : $this->baDesc->jsonSerialize(),
            'paDesc' => null === $this->paDesc ? null : $this->paDesc->jsonSerialize(),
        ];

        return \Akeeba\Passwordless\Webauthn\MetadataService\Utils::filterNullValues($data);
    }
}
