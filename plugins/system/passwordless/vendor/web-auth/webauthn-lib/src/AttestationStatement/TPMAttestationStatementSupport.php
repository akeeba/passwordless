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
use Akeeba\Passwordless\Cose\Algorithms;
use Akeeba\Passwordless\Cose\Key\Ec2Key;
use Akeeba\Passwordless\Cose\Key\Key;
use Akeeba\Passwordless\Cose\Key\OkpKey;
use Akeeba\Passwordless\Cose\Key\RsaKey;
use function count;
use function in_array;
use InvalidArgumentException;
use function is_array;
use RuntimeException;
use Akeeba\Passwordless\Safe\DateTimeImmutable;
use function Akeeba\Passwordless\Safe\sprintf;
use function Akeeba\Passwordless\Safe\unpack;
use Akeeba\Passwordless\Webauthn\AuthenticatorData;
use Akeeba\Passwordless\Webauthn\CertificateToolbox;
use Akeeba\Passwordless\Webauthn\StringStream;
use Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath;
use Akeeba\Passwordless\Webauthn\TrustPath\EcdaaKeyIdTrustPath;

final class TPMAttestationStatementSupport implements \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupport
{
    public function name(): string
    {
        return 'tpm';
    }

    /**
     * @param mixed[] $attestation
     */
    public function load(array $attestation): \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement
    {
        \Akeeba\Passwordless\Assert\Assertion::keyExists($attestation, 'attStmt', 'Invalid attestation object');
        \Akeeba\Passwordless\Assert\Assertion::keyNotExists($attestation['attStmt'], 'ecdaaKeyId', 'ECDAA not supported');
        foreach (['ver', 'ver', 'sig', 'alg', 'certInfo', 'pubArea'] as $key) {
            \Akeeba\Passwordless\Assert\Assertion::keyExists($attestation['attStmt'], $key, \Akeeba\Passwordless\Safe\sprintf('The attestation statement value "%s" is missing.', $key));
        }
        \Akeeba\Passwordless\Assert\Assertion::eq('2.0', $attestation['attStmt']['ver'], 'Invalid attestation object');

        $certInfo = $this->checkCertInfo($attestation['attStmt']['certInfo']);
        \Akeeba\Passwordless\Assert\Assertion::eq('8017', bin2hex($certInfo['type']), 'Invalid attestation object');

        $pubArea = $this->checkPubArea($attestation['attStmt']['pubArea']);
        $pubAreaAttestedNameAlg = mb_substr($certInfo['attestedName'], 0, 2, '8bit');
        $pubAreaHash = hash($this->getTPMHash($pubAreaAttestedNameAlg), $attestation['attStmt']['pubArea'], true);
        $attestedName = $pubAreaAttestedNameAlg.$pubAreaHash;
        \Akeeba\Passwordless\Assert\Assertion::eq($attestedName, $certInfo['attestedName'], 'Invalid attested name');

        $attestation['attStmt']['parsedCertInfo'] = $certInfo;
        $attestation['attStmt']['parsedPubArea'] = $pubArea;

        $certificates = \Akeeba\Passwordless\Webauthn\CertificateToolbox::convertAllDERToPEM($attestation['attStmt']['x5c']);
        \Akeeba\Passwordless\Assert\Assertion::minCount($certificates, 1, 'The attestation statement value "x5c" must be a list with at least one certificate.');

        return \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement::createAttCA(
            $this->name(),
            $attestation['attStmt'],
            new \Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath($certificates)
        );
    }

    public function isValid(string $clientDataJSONHash, \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement $attestationStatement, \Akeeba\Passwordless\Webauthn\AuthenticatorData $authenticatorData): bool
    {
        $attToBeSigned = $authenticatorData->getAuthData().$clientDataJSONHash;
        $attToBeSignedHash = hash(\Akeeba\Passwordless\Cose\Algorithms::getHashAlgorithmFor((int) $attestationStatement->get('alg')), $attToBeSigned, true);
        \Akeeba\Passwordless\Assert\Assertion::eq($attestationStatement->get('parsedCertInfo')['extraData'], $attToBeSignedHash, 'Invalid attestation hash');
        $this->checkUniquePublicKey(
            $attestationStatement->get('parsedPubArea')['unique'],
            $authenticatorData->getAttestedCredentialData()->getCredentialPublicKey()
        );

        switch (true) {
            case $attestationStatement->getTrustPath() instanceof \Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath:
                return $this->processWithCertificate($clientDataJSONHash, $attestationStatement, $authenticatorData);
            case $attestationStatement->getTrustPath() instanceof \Akeeba\Passwordless\Webauthn\TrustPath\EcdaaKeyIdTrustPath:
                return $this->processWithECDAA();
            default:
                throw new InvalidArgumentException('Unsupported attestation statement');
        }
    }

    private function checkUniquePublicKey(string $unique, string $cborPublicKey): void
    {
        $cborDecoder = new \Akeeba\Passwordless\CBOR\Decoder(new \Akeeba\Passwordless\CBOR\Tag\TagObjectManager(), new \Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManager());
        $publicKey = $cborDecoder->decode(new \Akeeba\Passwordless\Webauthn\StringStream($cborPublicKey));
        \Akeeba\Passwordless\Assert\Assertion::isInstanceOf($publicKey, \Akeeba\Passwordless\CBOR\MapObject::class, 'Invalid public key');
        $key = new \Akeeba\Passwordless\Cose\Key\Key($publicKey->getNormalizedData(false));

        switch ($key->type()) {
            case \Akeeba\Passwordless\Cose\Key\Key::TYPE_OKP:
                $uniqueFromKey = (new \Akeeba\Passwordless\Cose\Key\OkpKey($key->getData()))->x();
                break;
            case \Akeeba\Passwordless\Cose\Key\Key::TYPE_EC2:
                $ec2Key = new \Akeeba\Passwordless\Cose\Key\Ec2Key($key->getData());
                $uniqueFromKey = "\x04".$ec2Key->x().$ec2Key->y();
                break;
            case \Akeeba\Passwordless\Cose\Key\Key::TYPE_RSA:
                $uniqueFromKey = (new \Akeeba\Passwordless\Cose\Key\RsaKey($key->getData()))->n();
                break;
            default:
                throw new InvalidArgumentException('Invalid or unsupported key type.');
        }

        \Akeeba\Passwordless\Assert\Assertion::eq($unique, $uniqueFromKey, 'Invalid pubArea.unique value');
    }

    /**
     * @return mixed[]
     */
    private function checkCertInfo(string $data): array
    {
        $certInfo = new \Akeeba\Passwordless\Webauthn\StringStream($data);

        $magic = $certInfo->read(4);
        \Akeeba\Passwordless\Assert\Assertion::eq('ff544347', bin2hex($magic), 'Invalid attestation object');

        $type = $certInfo->read(2);

        $qualifiedSignerLength = \Akeeba\Passwordless\Safe\unpack('n', $certInfo->read(2))[1];
        $qualifiedSigner = $certInfo->read($qualifiedSignerLength); //Ignored

        $extraDataLength = \Akeeba\Passwordless\Safe\unpack('n', $certInfo->read(2))[1];
        $extraData = $certInfo->read($extraDataLength);

        $clockInfo = $certInfo->read(17); //Ignore

        $firmwareVersion = $certInfo->read(8);

        $attestedNameLength = \Akeeba\Passwordless\Safe\unpack('n', $certInfo->read(2))[1];
        $attestedName = $certInfo->read($attestedNameLength);

        $attestedQualifiedNameLength = \Akeeba\Passwordless\Safe\unpack('n', $certInfo->read(2))[1];
        $attestedQualifiedName = $certInfo->read($attestedQualifiedNameLength); //Ignore
        \Akeeba\Passwordless\Assert\Assertion::true($certInfo->isEOF(), 'Invalid certificate information. Presence of extra bytes.');
        $certInfo->close();

        return [
            'magic' => $magic,
            'type' => $type,
            'qualifiedSigner' => $qualifiedSigner,
            'extraData' => $extraData,
            'clockInfo' => $clockInfo,
            'firmwareVersion' => $firmwareVersion,
            'attestedName' => $attestedName,
            'attestedQualifiedName' => $attestedQualifiedName,
        ];
    }

    /**
     * @return mixed[]
     */
    private function checkPubArea(string $data): array
    {
        $pubArea = new \Akeeba\Passwordless\Webauthn\StringStream($data);

        $type = $pubArea->read(2);

        $nameAlg = $pubArea->read(2);

        $objectAttributes = $pubArea->read(4);

        $authPolicyLength = \Akeeba\Passwordless\Safe\unpack('n', $pubArea->read(2))[1];
        $authPolicy = $pubArea->read($authPolicyLength);

        $parameters = $this->getParameters($type, $pubArea);

        $uniqueLength = \Akeeba\Passwordless\Safe\unpack('n', $pubArea->read(2))[1];
        $unique = $pubArea->read($uniqueLength);
        \Akeeba\Passwordless\Assert\Assertion::true($pubArea->isEOF(), 'Invalid public area. Presence of extra bytes.');
        $pubArea->close();

        return [
            'type' => $type,
            'nameAlg' => $nameAlg,
            'objectAttributes' => $objectAttributes,
            'authPolicy' => $authPolicy,
            'parameters' => $parameters,
            'unique' => $unique,
        ];
    }

    /**
     * @return mixed[]
     */
    private function getParameters(string $type, \Akeeba\Passwordless\Webauthn\StringStream $stream): array
    {
        switch (bin2hex($type)) {
            case '0001':
            case '0014':
            case '0016':
                return [
                    'symmetric' => $stream->read(2),
                    'scheme' => $stream->read(2),
                    'keyBits' => \Akeeba\Passwordless\Safe\unpack('n', $stream->read(2))[1],
                    'exponent' => $this->getExponent($stream->read(4)),
                ];
            case '0018':
                return [
                    'symmetric' => $stream->read(2),
                    'scheme' => $stream->read(2),
                    'curveId' => $stream->read(2),
                    'kdf' => $stream->read(2),
                ];
            default:
                throw new InvalidArgumentException('Unsupported type');
        }
    }

    private function getExponent(string $exponent): string
    {
        return '00000000' === bin2hex($exponent) ? Base64Url::decode('AQAB') : $exponent;
    }

    private function getTPMHash(string $nameAlg): string
    {
        switch (bin2hex($nameAlg)) {
            case '0004':
                return 'sha1'; //: "TPM_ALG_SHA1",
            case '000b':
                return 'sha256'; //: "TPM_ALG_SHA256",
            case '000c':
                return 'sha384'; //: "TPM_ALG_SHA384",
            case '000d':
                return 'sha512'; //: "TPM_ALG_SHA512",
            default:
                throw new InvalidArgumentException('Unsupported hash algorithm');
        }
    }

    private function processWithCertificate(string $clientDataJSONHash, \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement $attestationStatement, \Akeeba\Passwordless\Webauthn\AuthenticatorData $authenticatorData): bool
    {
        $trustPath = $attestationStatement->getTrustPath();
        \Akeeba\Passwordless\Assert\Assertion::isInstanceOf($trustPath, \Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath::class, 'Invalid trust path');

        $certificates = $trustPath->getCertificates();

        // Check certificate CA chain and returns the Attestation Certificate
        $this->checkCertificate($certificates[0], $authenticatorData);

        // Get the COSE algorithm identifier and the corresponding OpenSSL one
        $coseAlgorithmIdentifier = (int) $attestationStatement->get('alg');
        $opensslAlgorithmIdentifier = \Akeeba\Passwordless\Cose\Algorithms::getOpensslAlgorithmFor($coseAlgorithmIdentifier);

        $result = openssl_verify($attestationStatement->get('certInfo'), $attestationStatement->get('sig'), $certificates[0], $opensslAlgorithmIdentifier);

        return 1 === $result;
    }

    private function checkCertificate(string $attestnCert, \Akeeba\Passwordless\Webauthn\AuthenticatorData $authenticatorData): void
    {
        $parsed = openssl_x509_parse($attestnCert);
        \Akeeba\Passwordless\Assert\Assertion::isArray($parsed, 'Invalid certificate');

        //Check version
        \Akeeba\Passwordless\Assert\Assertion::false(!isset($parsed['version']) || 2 !== $parsed['version'], 'Invalid certificate version');

        //Check subject field is empty
        \Akeeba\Passwordless\Assert\Assertion::false(!isset($parsed['subject']) || !is_array($parsed['subject']) || 0 !== count($parsed['subject']), 'Invalid certificate name. The Subject should be empty');

        // Check period of validity
        \Akeeba\Passwordless\Assert\Assertion::keyExists($parsed, 'validFrom_time_t', 'Invalid certificate start date.');
        \Akeeba\Passwordless\Assert\Assertion::integer($parsed['validFrom_time_t'], 'Invalid certificate start date.');
        $startDate = (new \Akeeba\Passwordless\Safe\DateTimeImmutable())->setTimestamp($parsed['validFrom_time_t']);
        \Akeeba\Passwordless\Assert\Assertion::true($startDate < new \Akeeba\Passwordless\Safe\DateTimeImmutable(), 'Invalid certificate start date.');

        \Akeeba\Passwordless\Assert\Assertion::keyExists($parsed, 'validTo_time_t', 'Invalid certificate end date.');
        \Akeeba\Passwordless\Assert\Assertion::integer($parsed['validTo_time_t'], 'Invalid certificate end date.');
        $endDate = (new \Akeeba\Passwordless\Safe\DateTimeImmutable())->setTimestamp($parsed['validTo_time_t']);
        \Akeeba\Passwordless\Assert\Assertion::true($endDate > new \Akeeba\Passwordless\Safe\DateTimeImmutable(), 'Invalid certificate end date.');

        //Check extensions
        \Akeeba\Passwordless\Assert\Assertion::false(!isset($parsed['extensions']) || !is_array($parsed['extensions']), 'Certificate extensions are missing');

        //Check subjectAltName
        \Akeeba\Passwordless\Assert\Assertion::false(!isset($parsed['extensions']['subjectAltName']), 'The "subjectAltName" is missing');

        //Check extendedKeyUsage
        \Akeeba\Passwordless\Assert\Assertion::false(!isset($parsed['extensions']['extendedKeyUsage']), 'The "subjectAltName" is missing');
        \Akeeba\Passwordless\Assert\Assertion::eq($parsed['extensions']['extendedKeyUsage'], '2.23.133.8.3', 'The "extendedKeyUsage" is invalid');

        // id-fido-gen-ce-aaguid OID check
        \Akeeba\Passwordless\Assert\Assertion::false(in_array('1.3.6.1.4.1.45724.1.1.4', $parsed['extensions'], true) && !hash_equals($authenticatorData->getAttestedCredentialData()->getAaguid()->getBytes(), $parsed['extensions']['1.3.6.1.4.1.45724.1.1.4']), 'The value of the "aaguid" does not match with the certificate');
    }

    private function processWithECDAA(): bool
    {
        throw new RuntimeException('ECDAA not supported');
    }
}
