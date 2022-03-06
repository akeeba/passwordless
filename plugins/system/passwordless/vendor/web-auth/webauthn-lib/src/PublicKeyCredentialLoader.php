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

use function array_key_exists;
use Akeeba\Passwordless\Assert\Assertion;
use Akeeba\Passwordless\Base64Url\Base64Url;
use Akeeba\Passwordless\CBOR\Decoder;
use Akeeba\Passwordless\CBOR\MapObject;
use Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManager;
use Akeeba\Passwordless\CBOR\Tag\TagObjectManager;
use InvalidArgumentException;
use function ord;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Akeeba\Passwordless\Ramsey\Uuid\Uuid;
use function Akeeba\Passwordless\Safe\json_decode;
use function Akeeba\Passwordless\Safe\sprintf;
use function Akeeba\Passwordless\Safe\unpack;
use Throwable;
use Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObjectLoader;
use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputsLoader;

class PublicKeyCredentialLoader
{
    private const FLAG_AT = 0b01000000;
    private const FLAG_ED = 0b10000000;

    /**
     * @var AttestationObjectLoader
     */
    private $attestationObjectLoader;

    /**
     * @var Decoder
     */
    private $decoder;

    /**
     * @var LoggerInterface
     */
    private $logger;

    public function __construct(\Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObjectLoader $attestationObjectLoader, ?LoggerInterface $logger = null)
    {
        if (null !== $logger) {
            @trigger_error('The argument "logger" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setLogger".', E_USER_DEPRECATED);
        }
        $this->decoder = new \Akeeba\Passwordless\CBOR\Decoder(new \Akeeba\Passwordless\CBOR\Tag\TagObjectManager(), new \Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManager());
        $this->attestationObjectLoader = $attestationObjectLoader;
        $this->logger = $logger ?? new NullLogger();
    }

    public static function create(\Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObjectLoader $attestationObjectLoader): self
    {
        return new self($attestationObjectLoader);
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    /**
     * @param mixed[] $json
     */
    public function loadArray(array $json): \Akeeba\Passwordless\Webauthn\PublicKeyCredential
    {
        $this->logger->info('Trying to load data from an array', ['data' => $json]);
        try {
            foreach (['id', 'rawId', 'type'] as $key) {
                \Akeeba\Passwordless\Assert\Assertion::keyExists($json, $key, \Akeeba\Passwordless\Safe\sprintf('The parameter "%s" is missing', $key));
                \Akeeba\Passwordless\Assert\Assertion::string($json[$key], \Akeeba\Passwordless\Safe\sprintf('The parameter "%s" shall be a string', $key));
            }
            \Akeeba\Passwordless\Assert\Assertion::keyExists($json, 'response', 'The parameter "response" is missing');
            \Akeeba\Passwordless\Assert\Assertion::isArray($json['response'], 'The parameter "response" shall be an array');
            \Akeeba\Passwordless\Assert\Assertion::eq($json['type'], 'public-key', \Akeeba\Passwordless\Safe\sprintf('Unsupported type "%s"', $json['type']));

            $id = Base64Url::decode($json['id']);
            $rawId = Base64Url::decode($json['rawId']);
            \Akeeba\Passwordless\Assert\Assertion::true(hash_equals($id, $rawId));

            $publicKeyCredential = new \Akeeba\Passwordless\Webauthn\PublicKeyCredential(
                $json['id'],
                $json['type'],
                $rawId,
                $this->createResponse($json['response'])
            );
            $this->logger->info('The data has been loaded');
            $this->logger->debug('Public Key Credential', ['publicKeyCredential' => $publicKeyCredential]);

            return $publicKeyCredential;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    public function load(string $data): \Akeeba\Passwordless\Webauthn\PublicKeyCredential
    {
        $this->logger->info('Trying to load data from a string', ['data' => $data]);
        try {
            $json = \Akeeba\Passwordless\Safe\json_decode($data, true);

            return $this->loadArray($json);
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    /**
     * @param mixed[] $response
     */
    private function createResponse(array $response): \Akeeba\Passwordless\Webauthn\AuthenticatorResponse
    {
        \Akeeba\Passwordless\Assert\Assertion::keyExists($response, 'clientDataJSON', 'Invalid data. The parameter "clientDataJSON" is missing');
        \Akeeba\Passwordless\Assert\Assertion::string($response['clientDataJSON'], 'Invalid data. The parameter "clientDataJSON" is invalid');
        switch (true) {
            case array_key_exists('attestationObject', $response):
                \Akeeba\Passwordless\Assert\Assertion::string($response['attestationObject'], 'Invalid data. The parameter "attestationObject   " is invalid');
                $attestationObject = $this->attestationObjectLoader->load($response['attestationObject']);

                return new \Akeeba\Passwordless\Webauthn\AuthenticatorAttestationResponse(\Akeeba\Passwordless\Webauthn\CollectedClientData::createFormJson($response['clientDataJSON']), $attestationObject);
            case array_key_exists('authenticatorData', $response) && array_key_exists('signature', $response):
                $authData = Base64Url::decode($response['authenticatorData']);

                $authDataStream = new \Akeeba\Passwordless\Webauthn\StringStream($authData);
                $rp_id_hash = $authDataStream->read(32);
                $flags = $authDataStream->read(1);
                $signCount = $authDataStream->read(4);
                $signCount = \Akeeba\Passwordless\Safe\unpack('N', $signCount)[1];

                $attestedCredentialData = null;
                if (0 !== (ord($flags) & self::FLAG_AT)) {
                    $aaguid = \Akeeba\Passwordless\Ramsey\Uuid\Uuid::fromBytes($authDataStream->read(16));
                    $credentialLength = $authDataStream->read(2);
                    $credentialLength = \Akeeba\Passwordless\Safe\unpack('n', $credentialLength)[1];
                    $credentialId = $authDataStream->read($credentialLength);
                    $credentialPublicKey = $this->decoder->decode($authDataStream);
                    \Akeeba\Passwordless\Assert\Assertion::isInstanceOf($credentialPublicKey, \Akeeba\Passwordless\CBOR\MapObject::class, 'The data does not contain a valid credential public key.');
                    $attestedCredentialData = new \Akeeba\Passwordless\Webauthn\AttestedCredentialData($aaguid, $credentialId, (string) $credentialPublicKey);
                }

                $extension = null;
                if (0 !== (ord($flags) & self::FLAG_ED)) {
                    $extension = $this->decoder->decode($authDataStream);
                    $extension = \Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputsLoader::load($extension);
                }
                \Akeeba\Passwordless\Assert\Assertion::true($authDataStream->isEOF(), 'Invalid authentication data. Presence of extra bytes.');
                $authDataStream->close();
                $authenticatorData = new \Akeeba\Passwordless\Webauthn\AuthenticatorData($authData, $rp_id_hash, $flags, $signCount, $attestedCredentialData, $extension);

                return new \Akeeba\Passwordless\Webauthn\AuthenticatorAssertionResponse(
                    \Akeeba\Passwordless\Webauthn\CollectedClientData::createFormJson($response['clientDataJSON']),
                    $authenticatorData,
                    Base64Url::decode($response['signature']),
                    $response['userHandle'] ?? null
                );
            default:
                throw new InvalidArgumentException('Unable to create the response object');
        }
    }
}
