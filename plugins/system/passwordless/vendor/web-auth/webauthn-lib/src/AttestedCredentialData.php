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
use JsonSerializable;
use Akeeba\Passwordless\Ramsey\Uuid\Uuid;
use Akeeba\Passwordless\Ramsey\Uuid\UuidInterface;
use function Akeeba\Passwordless\Safe\base64_decode;

/**
 * @see https://www.w3.org/TR/webauthn/#sec-attested-credential-data
 */
class AttestedCredentialData implements JsonSerializable
{
    /**
     * @var UuidInterface
     */
    private $aaguid;

    /**
     * @var string
     */
    private $credentialId;

    /**
     * @var string|null
     */
    private $credentialPublicKey;

    public function __construct(\Akeeba\Passwordless\Ramsey\Uuid\UuidInterface $aaguid, string $credentialId, ?string $credentialPublicKey)
    {
        $this->aaguid = $aaguid;
        $this->credentialId = $credentialId;
        $this->credentialPublicKey = $credentialPublicKey;
    }

    public function getAaguid(): \Akeeba\Passwordless\Ramsey\Uuid\UuidInterface
    {
        return $this->aaguid;
    }

    public function setAaguid(\Akeeba\Passwordless\Ramsey\Uuid\UuidInterface $aaguid): void
    {
        $this->aaguid = $aaguid;
    }

    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    public function getCredentialPublicKey(): ?string
    {
        return $this->credentialPublicKey;
    }

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): self
    {
        \Akeeba\Passwordless\Assert\Assertion::keyExists($json, 'aaguid', 'Invalid input. "aaguid" is missing.');
        \Akeeba\Passwordless\Assert\Assertion::keyExists($json, 'credentialId', 'Invalid input. "credentialId" is missing.');
        switch (true) {
            case 36 === mb_strlen($json['aaguid'], '8bit'):
                $uuid = \Akeeba\Passwordless\Ramsey\Uuid\Uuid::fromString($json['aaguid']);
                break;
            default: // Kept for compatibility with old format
                $decoded = \Akeeba\Passwordless\Safe\base64_decode($json['aaguid'], true);
                $uuid = \Akeeba\Passwordless\Ramsey\Uuid\Uuid::fromBytes($decoded);
        }
        $credentialId = \Akeeba\Passwordless\Safe\base64_decode($json['credentialId'], true);

        $credentialPublicKey = null;
        if (isset($json['credentialPublicKey'])) {
            $credentialPublicKey = \Akeeba\Passwordless\Safe\base64_decode($json['credentialPublicKey'], true);
        }

        return new self(
            $uuid,
            $credentialId,
            $credentialPublicKey
        );
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        $result = [
            'aaguid' => $this->aaguid->toString(),
            'credentialId' => base64_encode($this->credentialId),
        ];
        if (null !== $this->credentialPublicKey) {
            $result['credentialPublicKey'] = base64_encode($this->credentialPublicKey);
        }

        return $result;
    }
}
