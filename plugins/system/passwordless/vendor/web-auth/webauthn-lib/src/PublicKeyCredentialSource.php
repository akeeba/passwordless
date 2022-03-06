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

use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use Akeeba\Passwordless\Base64Url\Akeeba\Passwordless\Base64Url;
use InvalidArgumentException;
use JsonSerializable;
use Akeeba\Passwordless\Ramsey\Uuid\Uuid;
use Akeeba\Passwordless\Ramsey\Uuid\UuidInterface;
use function Akeeba\Passwordless\Safe\base64_decode;
use function Akeeba\Passwordless\Safe\sprintf;
use Throwable;
use Akeeba\Passwordless\Webauthn\TrustPath\TrustPath;
use Akeeba\Passwordless\Webauthn\TrustPath\TrustPathLoader;

/**
 * @see https://www.w3.org/TR/webauthn/#iface-pkcredential
 */
class PublicKeyCredentialSource implements JsonSerializable
{
    /**
     * @var string
     */
    protected $publicKeyCredentialId;

    /**
     * @var string
     */
    protected $type;

    /**
     * @var string[]
     */
    protected $transports;

    /**
     * @var string
     */
    protected $attestationType;

    /**
     * @var TrustPath
     */
    protected $trustPath;

    /**
     * @var UuidInterface
     */
    protected $aaguid;

    /**
     * @var string
     */
    protected $credentialPublicKey;

    /**
     * @var string
     */
    protected $userHandle;

    /**
     * @var int
     */
    protected $counter;

    /**
     * @var array|null
     */
    protected $otherUI;

    /**
     * @param string[] $transports
     */
    public function __construct(string $publicKeyCredentialId, string $type, array $transports, string $attestationType, \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath $trustPath, \Akeeba\Passwordless\Ramsey\Uuid\UuidInterface $aaguid, string $credentialPublicKey, string $userHandle, int $counter, ?array $otherUI = null)
    {
        $this->publicKeyCredentialId = $publicKeyCredentialId;
        $this->type = $type;
        $this->transports = $transports;
        $this->aaguid = $aaguid;
        $this->credentialPublicKey = $credentialPublicKey;
        $this->userHandle = $userHandle;
        $this->counter = $counter;
        $this->attestationType = $attestationType;
        $this->trustPath = $trustPath;
        $this->otherUI = $otherUI;
    }

    public function getPublicKeyCredentialId(): string
    {
        return $this->publicKeyCredentialId;
    }

    public function getPublicKeyCredentialDescriptor(): \Akeeba\Passwordless\Webauthn\PublicKeyCredentialDescriptor
    {
        return new \Akeeba\Passwordless\Webauthn\PublicKeyCredentialDescriptor(
            $this->type,
            $this->publicKeyCredentialId,
            $this->transports
        );
    }

    public function getAttestationType(): string
    {
        return $this->attestationType;
    }

    public function getTrustPath(): \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath
    {
        return $this->trustPath;
    }

    public function getAttestedCredentialData(): \Akeeba\Passwordless\Webauthn\AttestedCredentialData
    {
        return new \Akeeba\Passwordless\Webauthn\AttestedCredentialData(
            $this->aaguid,
            $this->publicKeyCredentialId,
            $this->credentialPublicKey
        );
    }

    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @return string[]
     */
    public function getTransports(): array
    {
        return $this->transports;
    }

    public function getAaguid(): \Akeeba\Passwordless\Ramsey\Uuid\UuidInterface
    {
        return $this->aaguid;
    }

    public function getCredentialPublicKey(): string
    {
        return $this->credentialPublicKey;
    }

    public function getUserHandle(): string
    {
        return $this->userHandle;
    }

    public function getCounter(): int
    {
        return $this->counter;
    }

    public function setCounter(int $counter): void
    {
        $this->counter = $counter;
    }

    public function getOtherUI(): ?array
    {
        return $this->otherUI;
    }

    public function setOtherUI(?array $otherUI): self
    {
        $this->otherUI = $otherUI;

        return $this;
    }

    /**
     * @param mixed[] $data
     */
    public static function createFromArray(array $data): self
    {
        $keys = array_keys(get_class_vars(self::class));
        foreach ($keys as $key) {
            if ('otherUI' === $key) {
                continue;
            }
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($data, $key, \Akeeba\Passwordless\Safe\sprintf('The parameter "%s" is missing', $key));
        }
        switch (true) {
            case 36 === mb_strlen($data['aaguid'], '8bit'):
                $uuid = \Akeeba\Passwordless\Ramsey\Uuid\Uuid::fromString($data['aaguid']);
                break;
            default: // Kept for compatibility with old format
                $decoded = \Akeeba\Passwordless\Safe\base64_decode($data['aaguid'], true);
                $uuid = \Akeeba\Passwordless\Ramsey\Uuid\Uuid::fromBytes($decoded);
        }

        try {
            return new self(
                \Akeeba\Passwordless\Base64Url\Akeeba\Passwordless\Base64Url::decode($data['publicKeyCredentialId']),
                $data['type'],
                $data['transports'],
                $data['attestationType'],
                \Akeeba\Passwordless\Webauthn\TrustPath\TrustPathLoader::loadTrustPath($data['trustPath']),
                $uuid,
                \Akeeba\Passwordless\Base64Url\Akeeba\Passwordless\Base64Url::decode($data['credentialPublicKey']),
                \Akeeba\Passwordless\Base64Url\Akeeba\Passwordless\Base64Url::decode($data['userHandle']),
                $data['counter'],
                $data['otherUI'] ?? null
            );
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException('Unable to load the data', $throwable->getCode(), $throwable);
        }
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        return [
            'publicKeyCredentialId' => \Akeeba\Passwordless\Base64Url\Akeeba\Passwordless\Base64Url::encode($this->publicKeyCredentialId),
            'type' => $this->type,
            'transports' => $this->transports,
            'attestationType' => $this->attestationType,
            'trustPath' => $this->trustPath->jsonSerialize(),
            'aaguid' => $this->aaguid->toString(),
            'credentialPublicKey' => \Akeeba\Passwordless\Base64Url\Akeeba\Passwordless\Base64Url::encode($this->credentialPublicKey),
            'userHandle' => \Akeeba\Passwordless\Base64Url\Akeeba\Passwordless\Base64Url::encode($this->userHandle),
            'counter' => $this->counter,
            'otherUI' => $this->otherUI,
        ];
    }
}
