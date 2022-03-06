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
use Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManager;
use Akeeba\Passwordless\CBOR\Tag\TagObjectManager;
use Akeeba\Passwordless\Cose\Algorithms;
use Akeeba\Passwordless\Cose\Key\Ec2Key;
use Akeeba\Passwordless\Cose\Key\Key;
use Akeeba\Passwordless\Cose\Key\RsaKey;
use function count;
use Akeeba\Passwordless\FG\ASN1\ASNObject;
use Akeeba\Passwordless\FG\ASN1\ExplicitlyTaggedObject;
use Akeeba\Passwordless\FG\ASN1\Universal\OctetString;
use Akeeba\Passwordless\FG\ASN1\Universal\Sequence;
use function Akeeba\Passwordless\Safe\hex2bin;
use function Akeeba\Passwordless\Safe\openssl_pkey_get_public;
use function Akeeba\Passwordless\Safe\sprintf;
use Akeeba\Passwordless\Webauthn\AuthenticatorData;
use Akeeba\Passwordless\Webauthn\CertificateToolbox;
use Akeeba\Passwordless\Webauthn\StringStream;
use Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath;

final class AndroidKeyAttestationStatementSupport implements \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupport
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
        return 'android-key';
    }

    /**
     * @param mixed[] $attestation
     */
    public function load(array $attestation): \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($attestation, 'attStmt', 'Invalid attestation object');
        foreach (['sig', 'x5c', 'alg'] as $key) {
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($attestation['attStmt'], $key, \Akeeba\Passwordless\Safe\sprintf('The attestation statement value "%s" is missing.', $key));
        }
        $certificates = $attestation['attStmt']['x5c'];
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isArray($certificates, 'The attestation statement value "x5c" must be a list with at least one certificate.');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::greaterThan(count($certificates), 0, 'The attestation statement value "x5c" must be a list with at least one certificate.');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::allString($certificates, 'The attestation statement value "x5c" must be a list with at least one certificate.');
        $certificates = \Akeeba\Passwordless\Webauthn\CertificateToolbox::convertAllDERToPEM($certificates);

        return \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement::createBasic($attestation['fmt'], $attestation['attStmt'], new \Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath($certificates));
    }

    public function isValid(string $clientDataJSONHash, \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement $attestationStatement, \Akeeba\Passwordless\Webauthn\AuthenticatorData $authenticatorData): bool
    {
        $trustPath = $attestationStatement->getTrustPath();
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isInstanceOf($trustPath, \Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath::class, 'Invalid trust path');

        $certificates = $trustPath->getCertificates();

        //Decode leaf attestation certificate
        $leaf = $certificates[0];
        $this->checkCertificateAndGetPublicKey($leaf, $clientDataJSONHash, $authenticatorData);

        $signedData = $authenticatorData->getAuthData().$clientDataJSONHash;
        $alg = $attestationStatement->get('alg');

        return 1 === openssl_verify($signedData, $attestationStatement->get('sig'), $leaf, \Akeeba\Passwordless\Cose\Algorithms::getOpensslAlgorithmFor((int) $alg));
    }

    private function checkCertificateAndGetPublicKey(string $certificate, string $clientDataHash, \Akeeba\Passwordless\Webauthn\AuthenticatorData $authenticatorData): void
    {
        $resource = \Akeeba\Passwordless\Safe\openssl_pkey_get_public($certificate);
        $details = openssl_pkey_get_details($resource);
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isArray($details, 'Unable to read the certificate');

        //Check that authData publicKey matches the public key in the attestation certificate
        $attestedCredentialData = $authenticatorData->getAttestedCredentialData();
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::notNull($attestedCredentialData, 'No attested credential data found');
        $publicKeyData = $attestedCredentialData->getCredentialPublicKey();
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::notNull($publicKeyData, 'No attested public key found');
        $publicDataStream = new \Akeeba\Passwordless\Webauthn\StringStream($publicKeyData);
        $coseKey = $this->decoder->decode($publicDataStream)->getNormalizedData(false);
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($publicDataStream->isEOF(), 'Invalid public key data. Presence of extra bytes.');
        $publicDataStream->close();
        $publicKey = \Akeeba\Passwordless\Cose\Key\Key::createFromData($coseKey);

        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true(($publicKey instanceof \Akeeba\Passwordless\Cose\Key\Ec2Key) || ($publicKey instanceof \Akeeba\Passwordless\Cose\Key\RsaKey), 'Unsupported key type');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq($publicKey->asPEM(), $details['key'], 'Invalid key');

        /*---------------------------*/
        $certDetails = openssl_x509_parse($certificate);

        //Find Android KeyStore Extension with OID “1.3.6.1.4.1.11129.2.1.17” in certificate extensions
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isArray($certDetails, 'The certificate is not valid');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($certDetails, 'extensions', 'The certificate has no extension');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isArray($certDetails['extensions'], 'The certificate has no extension');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($certDetails['extensions'], '1.3.6.1.4.1.11129.2.1.17', 'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is missing');
        $extension = $certDetails['extensions']['1.3.6.1.4.1.11129.2.1.17'];
        $extensionAsAsn1 = \Akeeba\Passwordless\FG\ASN1\ASNObject::fromBinary($extension);
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isInstanceOf($extensionAsAsn1, \Akeeba\Passwordless\FG\ASN1\Universal\Sequence::class, 'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is invalid');
        $objects = $extensionAsAsn1->getChildren();

        //Check that attestationChallenge is set to the clientDataHash.
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($objects, 4, 'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is invalid');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isInstanceOf($objects[4], \Akeeba\Passwordless\FG\ASN1\Universal\OctetString::class, 'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is invalid');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq($clientDataHash, \Akeeba\Passwordless\Safe\hex2bin(($objects[4])->getContent()), 'The client data hash is not valid');

        //Check that both teeEnforced and softwareEnforced structures don’t contain allApplications(600) tag.
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($objects, 6, 'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is invalid');
        $softwareEnforcedFlags = $objects[6];
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isInstanceOf($softwareEnforcedFlags, \Akeeba\Passwordless\FG\ASN1\Universal\Sequence::class, 'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is invalid');
        $this->checkAbsenceOfAllApplicationsTag($softwareEnforcedFlags);

        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($objects, 7, 'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is invalid');
        $teeEnforcedFlags = $objects[6];
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isInstanceOf($teeEnforcedFlags, \Akeeba\Passwordless\FG\ASN1\Universal\Sequence::class, 'The certificate extension "1.3.6.1.4.1.11129.2.1.17" is invalid');
        $this->checkAbsenceOfAllApplicationsTag($teeEnforcedFlags);
    }

    private function checkAbsenceOfAllApplicationsTag(\Akeeba\Passwordless\FG\ASN1\Universal\Sequence $sequence): void
    {
        foreach ($sequence->getChildren() as $tag) {
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isInstanceOf($tag, \Akeeba\Passwordless\FG\ASN1\ExplicitlyTaggedObject::class, 'Invalid tag');
            /* @var ExplicitlyTaggedObject $tag */
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::notEq(600, (int) $tag->getTag(), 'Forbidden tag 600 found');
        }
    }
}
