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

use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use Akeeba\Passwordless\CBOR\Decoder;
use Akeeba\Passwordless\CBOR\MapObject;
use Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManager;
use Akeeba\Passwordless\CBOR\Tag\TagObjectManager;
use Akeeba\Passwordless\Cose\Key\Ec2Key;
use InvalidArgumentException;
use function Akeeba\Passwordless\Safe\openssl_pkey_get_public;
use function Akeeba\Passwordless\Safe\sprintf;
use Throwable;
use Akeeba\Passwordless\Webauthn\AuthenticatorData;
use Akeeba\Passwordless\Webauthn\CertificateToolbox;
use Akeeba\Passwordless\Webauthn\StringStream;
use Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath;

final class FidoU2FAttestationStatementSupport implements \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupport
{
    /**
     * @var Decoder
     */
    private $decoder;

    public function __construct()
    {
        $this->decoder = new \Akeeba\Passwordless\CBOR\Decoder(new \Akeeba\Passwordless\CBOR\Tag\TagObjectManager(), new \Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManager());
    }

    public function name(): string
    {
        return 'fido-u2f';
    }

    /**
     * @param mixed[] $attestation
     */
    public function load(array $attestation): \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($attestation, 'attStmt', 'Invalid attestation object');
        foreach (['sig', 'x5c'] as $key) {
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($attestation['attStmt'], $key, \Akeeba\Passwordless\Safe\sprintf('The attestation statement value "%s" is missing.', $key));
        }
        $certificates = $attestation['attStmt']['x5c'];
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isArray($certificates, 'The attestation statement value "x5c" must be a list with one certificate.');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::count($certificates, 1, 'The attestation statement value "x5c" must be a list with one certificate.');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::allString($certificates, 'The attestation statement value "x5c" must be a list with one certificate.');

        reset($certificates);
        $certificates = \Akeeba\Passwordless\Webauthn\CertificateToolbox::convertAllDERToPEM($certificates);
        $this->checkCertificate($certificates[0]);

        return \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement::createBasic($attestation['fmt'], $attestation['attStmt'], new \Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath($certificates));
    }

    public function isValid(string $clientDataJSONHash, \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement $attestationStatement, \Akeeba\Passwordless\Webauthn\AuthenticatorData $authenticatorData): bool
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq(
            $authenticatorData->getAttestedCredentialData()->getAaguid()->toString(),
            '00000000-0000-0000-0000-000000000000',
            'Invalid AAGUID for fido-u2f attestation statement. Shall be "00000000-0000-0000-0000-000000000000"'
        );
        $trustPath = $attestationStatement->getTrustPath();
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isInstanceOf($trustPath, \Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath::class, 'Invalid trust path');
        $dataToVerify = "\0";
        $dataToVerify .= $authenticatorData->getRpIdHash();
        $dataToVerify .= $clientDataJSONHash;
        $dataToVerify .= $authenticatorData->getAttestedCredentialData()->getCredentialId();
        $dataToVerify .= $this->extractPublicKey($authenticatorData->getAttestedCredentialData()->getCredentialPublicKey());

        return 1 === openssl_verify($dataToVerify, $attestationStatement->get('sig'), $trustPath->getCertificates()[0], OPENSSL_ALGO_SHA256);
    }

    private function extractPublicKey(?string $publicKey): string
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::notNull($publicKey, 'The attested credential data does not contain a valid public key.');

        $publicKeyStream = new \Akeeba\Passwordless\Webauthn\StringStream($publicKey);
        $coseKey = $this->decoder->decode($publicKeyStream);
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($publicKeyStream->isEOF(), 'Invalid public key. Presence of extra bytes.');
        $publicKeyStream->close();
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isInstanceOf($coseKey, \Akeeba\Passwordless\CBOR\MapObject::class, 'The attested credential data does not contain a valid public key.');

        $coseKey = $coseKey->getNormalizedData();
        $ec2Key = new \Akeeba\Passwordless\Cose\Key\Ec2Key($coseKey + [\Akeeba\Passwordless\Cose\Key\Ec2Key::TYPE => 2, \Akeeba\Passwordless\Cose\Key\Ec2Key::DATA_CURVE => \Akeeba\Passwordless\Cose\Key\Ec2Key::CURVE_P256]);

        return "\x04".$ec2Key->x().$ec2Key->y();
    }

    private function checkCertificate(string $publicKey): void
    {
        try {
            $resource = \Akeeba\Passwordless\Safe\openssl_pkey_get_public($publicKey);
            $details = openssl_pkey_get_details($resource);
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException('Invalid certificate or certificate chain', 0, $throwable);
        }
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isArray($details, 'Invalid certificate or certificate chain');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($details, 'ec', 'Invalid certificate or certificate chain');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($details['ec'], 'curve_name', 'Invalid certificate or certificate chain');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq($details['ec']['curve_name'], 'prime256v1', 'Invalid certificate or certificate chain');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($details['ec'], 'curve_oid', 'Invalid certificate or certificate chain');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq($details['ec']['curve_oid'], '1.2.840.10045.3.1.7', 'Invalid certificate or certificate chain');
    }
}
