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
use Akeeba\Passwordless\Base64Url\Base64Url;
use Akeeba\Passwordless\CBOR\Decoder;
use Akeeba\Passwordless\CBOR\MapObject;
use Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManager;
use Akeeba\Passwordless\CBOR\Tag\TagObjectManager;
use function ord;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Akeeba\Passwordless\Ramsey\Uuid\Uuid;
use function Akeeba\Passwordless\Safe\sprintf;
use function Akeeba\Passwordless\Safe\unpack;
use Throwable;
use Akeeba\Passwordless\Webauthn\AttestedCredentialData;
use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputsLoader;
use Akeeba\Passwordless\Webauthn\AuthenticatorData;
use Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatementRepository;
use Akeeba\Passwordless\Webauthn\StringStream;

class AttestationObjectLoader
{
    private const FLAG_AT = 0b01000000;
    private const FLAG_ED = 0b10000000;

    /**
     * @var Decoder
     */
    private $decoder;

    /**
     * @var AttestationStatementSupportManager
     */
    private $attestationStatementSupportManager;

    /**
     * @var LoggerInterface|null
     */
    private $logger;

    public function __construct(\Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupportManager $attestationStatementSupportManager, ?\Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatementRepository $metadataStatementRepository = null, ?LoggerInterface $logger = null)
    {
        if (null !== $metadataStatementRepository) {
            @trigger_error('The argument "metadataStatementRepository" is deprecated since version 3.2 and will be removed in 4.0. Please set `null` instead.', E_USER_DEPRECATED);
        }
        if (null !== $logger) {
            @trigger_error('The argument "logger" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setLogger" instead.', E_USER_DEPRECATED);
        }
        $this->decoder = new \Akeeba\Passwordless\CBOR\Decoder(new \Akeeba\Passwordless\CBOR\Tag\TagObjectManager(), new \Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManager());
        $this->attestationStatementSupportManager = $attestationStatementSupportManager;
        $this->logger = $logger ?? new NullLogger();
    }

    public static function create(\Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupportManager $attestationStatementSupportManager): self
    {
        return new self($attestationStatementSupportManager);
    }

    public function load(string $data): \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObject
    {
        try {
            $this->logger->info('Trying to load the data', ['data' => $data]);
            $decodedData = Base64Url::decode($data);
            $stream = new \Akeeba\Passwordless\Webauthn\StringStream($decodedData);
            $parsed = $this->decoder->decode($stream);

            $this->logger->info('Loading the Attestation Statement');
            $attestationObject = $parsed->getNormalizedData();
            \Akeeba\Passwordless\Assert\Assertion::true($stream->isEOF(), 'Invalid attestation object. Presence of extra bytes.');
            $stream->close();
            \Akeeba\Passwordless\Assert\Assertion::isArray($attestationObject, 'Invalid attestation object');
            \Akeeba\Passwordless\Assert\Assertion::keyExists($attestationObject, 'authData', 'Invalid attestation object');
            \Akeeba\Passwordless\Assert\Assertion::keyExists($attestationObject, 'fmt', 'Invalid attestation object');
            \Akeeba\Passwordless\Assert\Assertion::keyExists($attestationObject, 'attStmt', 'Invalid attestation object');
            $authData = $attestationObject['authData'];

            $attestationStatementSupport = $this->attestationStatementSupportManager->get($attestationObject['fmt']);
            $attestationStatement = $attestationStatementSupport->load($attestationObject);
            $this->logger->info('Attestation Statement loaded');
            $this->logger->debug('Attestation Statement loaded', ['attestationStatement' => $attestationStatement]);

            $authDataStream = new \Akeeba\Passwordless\Webauthn\StringStream($authData);
            $rp_id_hash = $authDataStream->read(32);
            $flags = $authDataStream->read(1);
            $signCount = $authDataStream->read(4);
            $signCount = \Akeeba\Passwordless\Safe\unpack('N', $signCount)[1];
            $this->logger->debug(\Akeeba\Passwordless\Safe\sprintf('Signature counter: %d', $signCount));

            $attestedCredentialData = null;
            if (0 !== (ord($flags) & self::FLAG_AT)) {
                $this->logger->info('Attested Credential Data is present');
                $aaguid = \Akeeba\Passwordless\Ramsey\Uuid\Uuid::fromBytes($authDataStream->read(16));
                $credentialLength = $authDataStream->read(2);
                $credentialLength = \Akeeba\Passwordless\Safe\unpack('n', $credentialLength)[1];
                $credentialId = $authDataStream->read($credentialLength);
                $credentialPublicKey = $this->decoder->decode($authDataStream);
                \Akeeba\Passwordless\Assert\Assertion::isInstanceOf($credentialPublicKey, \Akeeba\Passwordless\CBOR\MapObject::class, 'The data does not contain a valid credential public key.');
                $attestedCredentialData = new \Akeeba\Passwordless\Webauthn\AttestedCredentialData($aaguid, $credentialId, (string) $credentialPublicKey);
                $this->logger->info('Attested Credential Data loaded');
                $this->logger->debug('Attested Credential Data loaded', ['at' => $attestedCredentialData]);
            }

            $extension = null;
            if (0 !== (ord($flags) & self::FLAG_ED)) {
                $this->logger->info('Extension Data loaded');
                $extension = $this->decoder->decode($authDataStream);
                $extension = \Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputsLoader::load($extension);
                $this->logger->info('Extension Data loaded');
                $this->logger->debug('Extension Data loaded', ['ed' => $extension]);
            }
            \Akeeba\Passwordless\Assert\Assertion::true($authDataStream->isEOF(), 'Invalid authentication data. Presence of extra bytes.');
            $authDataStream->close();

            $authenticatorData = new \Akeeba\Passwordless\Webauthn\AuthenticatorData($authData, $rp_id_hash, $flags, $signCount, $attestedCredentialData, $extension);
            $attestationObject = new \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObject($data, $attestationStatement, $authenticatorData);
            $this->logger->info('Attestation Object loaded');
            $this->logger->debug('Attestation Object', ['ed' => $attestationObject]);

            return $attestationObject;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }
}
