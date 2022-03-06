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
use function count;
use function in_array;
use InvalidArgumentException;
use function is_string;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Akeeba\Passwordless\Ramsey\Uuid\Uuid;
use function Akeeba\Passwordless\Safe\parse_url;
use function Akeeba\Passwordless\Safe\sprintf;
use Throwable;
use Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObject;
use Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement;
use Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Akeeba\Passwordless\Webauthn\CertificateChainChecker\CertificateChainChecker;
use Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement;
use Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatementRepository;
use Akeeba\Passwordless\Webauthn\MetadataService\StatusReport;
use Akeeba\Passwordless\Webauthn\TokenBinding\TokenBindingHandler;
use Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath;
use Akeeba\Passwordless\Webauthn\TrustPath\EmptyTrustPath;

class AuthenticatorAttestationResponseValidator
{
    /**
     * @var AttestationStatementSupportManager
     */
    private $attestationStatementSupportManager;

    /**
     * @var PublicKeyCredentialSourceRepository
     */
    private $publicKeyCredentialSource;

    /**
     * @var TokenBindingHandler
     */
    private $tokenBindingHandler;

    /**
     * @var ExtensionOutputCheckerHandler
     */
    private $extensionOutputCheckerHandler;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var MetadataStatementRepository|null
     */
    private $metadataStatementRepository;

    /**
     * @var CertificateChainChecker|null
     */
    private $certificateChainChecker;

    public function __construct(\Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupportManager $attestationStatementSupportManager, \Akeeba\Passwordless\Webauthn\PublicKeyCredentialSourceRepository $publicKeyCredentialSource, \Akeeba\Passwordless\Webauthn\TokenBinding\TokenBindingHandler $tokenBindingHandler, \Akeeba\Passwordless\Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler $extensionOutputCheckerHandler, ?\Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatementRepository $metadataStatementRepository = null, ?LoggerInterface $logger = null)
    {
        if (null !== $logger) {
            @trigger_error('The argument "logger" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setLogger".', E_USER_DEPRECATED);
        }
        if (null !== $metadataStatementRepository) {
            @trigger_error('The argument "metadataStatementRepository" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setMetadataStatementRepository".', E_USER_DEPRECATED);
        }
        $this->attestationStatementSupportManager = $attestationStatementSupportManager;
        $this->publicKeyCredentialSource = $publicKeyCredentialSource;
        $this->tokenBindingHandler = $tokenBindingHandler;
        $this->extensionOutputCheckerHandler = $extensionOutputCheckerHandler;
        $this->metadataStatementRepository = $metadataStatementRepository;
        $this->logger = $logger ?? new NullLogger();
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    public function setCertificateChainChecker(\Akeeba\Passwordless\Webauthn\CertificateChainChecker\CertificateChainChecker $certificateChainChecker): self
    {
        $this->certificateChainChecker = $certificateChainChecker;

        return $this;
    }

    public function setMetadataStatementRepository(\Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatementRepository $metadataStatementRepository): self
    {
        $this->metadataStatementRepository = $metadataStatementRepository;

        return $this;
    }

    /**
     * @see https://www.w3.org/TR/webauthn/#registering-a-new-credential
     */
    public function check(\Akeeba\Passwordless\Webauthn\AuthenticatorAttestationResponse $authenticatorAttestationResponse, \Akeeba\Passwordless\Webauthn\PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, ServerRequestInterface $request, array $securedRelyingPartyId = []): \Akeeba\Passwordless\Webauthn\PublicKeyCredentialSource
    {
        try {
            $this->logger->info('Checking the authenticator attestation response', [
                'authenticatorAttestationResponse' => $authenticatorAttestationResponse,
                'publicKeyCredentialCreationOptions' => $publicKeyCredentialCreationOptions,
                'host' => $request->getUri()->getHost(),
            ]);
            /** @see 7.1.1 */
            //Nothing to do

            /** @see 7.1.2 */
            $C = $authenticatorAttestationResponse->getClientDataJSON();

            /** @see 7.1.3 */
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq('webauthn.create', $C->getType(), 'The client data type is not "webauthn.create".');

            /** @see 7.1.4 */
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true(hash_equals($publicKeyCredentialCreationOptions->getChallenge(), $C->getChallenge()), 'Invalid challenge.');

            /** @see 7.1.5 */
            $rpId = $publicKeyCredentialCreationOptions->getRp()->getId() ?? $request->getUri()->getHost();
            $facetId = $this->getFacetId($rpId, $publicKeyCredentialCreationOptions->getExtensions(), $authenticatorAttestationResponse->getAttestationObject()->getAuthData()->getExtensions());

            $parsedRelyingPartyId = \Akeeba\Passwordless\Safe\parse_url($C->getOrigin());
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isArray($parsedRelyingPartyId, \Akeeba\Passwordless\Safe\sprintf('The origin URI "%s" is not valid', $C->getOrigin()));
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($parsedRelyingPartyId, 'scheme', 'Invalid origin rpId.');
            $clientDataRpId = $parsedRelyingPartyId['host'] ?? '';
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::notEmpty($clientDataRpId, 'Invalid origin rpId.');
            $rpIdLength = mb_strlen($facetId);
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq(mb_substr('.'.$clientDataRpId, -($rpIdLength + 1)), '.'.$facetId, 'rpId mismatch.');

            if (!in_array($facetId, $securedRelyingPartyId, true)) {
                $scheme = $parsedRelyingPartyId['scheme'] ?? '';
                \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::eq('https', $scheme, 'Invalid scheme. HTTPS required.');
            }

            /** @see 7.1.6 */
            if (null !== $C->getTokenBinding()) {
                $this->tokenBindingHandler->check($C->getTokenBinding(), $request);
            }

            /** @see 7.1.7 */
            $clientDataJSONHash = hash('sha256', $authenticatorAttestationResponse->getClientDataJSON()->getRawData(), true);

            /** @see 7.1.8 */
            $attestationObject = $authenticatorAttestationResponse->getAttestationObject();

            /** @see 7.1.9 */
            $rpIdHash = hash('sha256', $facetId, true);
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true(hash_equals($rpIdHash, $attestationObject->getAuthData()->getRpIdHash()), 'rpId hash mismatch.');

            /** @see 7.1.10 */
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($attestationObject->getAuthData()->isUserPresent(), 'User was not present');
            /** @see 7.1.11 */
            if (\Akeeba\Passwordless\Webauthn\AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED === $publicKeyCredentialCreationOptions->getAuthenticatorSelection()->getUserVerification()) {
                \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($attestationObject->getAuthData()->isUserVerified(), 'User authentication required.');
            }

            /** @see 7.1.12 */
            $extensionsClientOutputs = $attestationObject->getAuthData()->getExtensions();
            if (null !== $extensionsClientOutputs) {
                $this->extensionOutputCheckerHandler->check(
                    $publicKeyCredentialCreationOptions->getExtensions(),
                    $extensionsClientOutputs
                );
            }

            /** @see 7.1.13 */
            $this->checkMetadataStatement($publicKeyCredentialCreationOptions, $attestationObject);
            $fmt = $attestationObject->getAttStmt()->getFmt();
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($this->attestationStatementSupportManager->has($fmt), 'Unsupported attestation statement format.');

            /** @see 7.1.14 */
            $attestationStatementSupport = $this->attestationStatementSupportManager->get($fmt);
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($attestationStatementSupport->isValid($clientDataJSONHash, $attestationObject->getAttStmt(), $attestationObject->getAuthData()), 'Invalid attestation statement.');

            /** @see 7.1.15 */
            /** @see 7.1.16 */
            /** @see 7.1.17 */
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($attestationObject->getAuthData()->hasAttestedCredentialData(), 'There is no attested credential data.');
            $attestedCredentialData = $attestationObject->getAuthData()->getAttestedCredentialData();
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::notNull($attestedCredentialData, 'There is no attested credential data.');
            $credentialId = $attestedCredentialData->getCredentialId();
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::null($this->publicKeyCredentialSource->findOneByCredentialId($credentialId), 'The credential ID already exists.');

            /** @see 7.1.18 */
            /** @see 7.1.19 */
            $publicKeyCredentialSource = $this->createPublicKeyCredentialSource(
                $credentialId,
                $attestedCredentialData,
                $attestationObject,
                $publicKeyCredentialCreationOptions->getUser()->getId()
            );
            $this->logger->info('The attestation is valid');
            $this->logger->debug('Public Key Credential Source', ['publicKeyCredentialSource' => $publicKeyCredentialSource]);

            return $publicKeyCredentialSource;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    private function checkCertificateChain(\Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement $attestationStatement, ?\Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement $metadataStatement): void
    {
        $trustPath = $attestationStatement->getTrustPath();
        if (!$trustPath instanceof \Akeeba\Passwordless\Webauthn\TrustPath\CertificateTrustPath) {
            return;
        }
        $authenticatorCertificates = $trustPath->getCertificates();

        if (null === $metadataStatement) {
            // @phpstan-ignore-next-line
            null === $this->certificateChainChecker ? \Akeeba\Passwordless\Webauthn\CertificateToolbox::checkChain($authenticatorCertificates) : $this->certificateChainChecker->check($authenticatorCertificates, [], null);

            return;
        }

        $metadataStatementCertificates = $metadataStatement->getAttestationRootCertificates();
        $rootStatementCertificates = $metadataStatement->getRootCertificates();
        foreach ($metadataStatementCertificates as $key => $metadataStatementCertificate) {
            $metadataStatementCertificates[$key] = \Akeeba\Passwordless\Webauthn\CertificateToolbox::fixPEMStructure($metadataStatementCertificate);
        }
        $trustedCertificates = array_merge(
            $metadataStatementCertificates,
            $rootStatementCertificates
        );

        // @phpstan-ignore-next-line
        null === $this->certificateChainChecker ? \Akeeba\Passwordless\Webauthn\CertificateToolbox::checkChain($authenticatorCertificates, $trustedCertificates) : $this->certificateChainChecker->check($authenticatorCertificates, $trustedCertificates);
    }

    private function checkMetadataStatement(\Akeeba\Passwordless\Webauthn\PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObject $attestationObject): void
    {
        $attestationStatement = $attestationObject->getAttStmt();
        $attestedCredentialData = $attestationObject->getAuthData()->getAttestedCredentialData();
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::notNull($attestedCredentialData, 'No attested credential data found');
        $aaguid = $attestedCredentialData->getAaguid()->toString();
        if (\Akeeba\Passwordless\Webauthn\PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE === $publicKeyCredentialCreationOptions->getAttestation()) {
            $this->logger->debug('No attestation is asked.');
            //No attestation is asked. We shall ensure that the data is anonymous.
            if (
                '00000000-0000-0000-0000-000000000000' === $aaguid
                && (\Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement::TYPE_NONE === $attestationStatement->getType() || \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement::TYPE_SELF === $attestationStatement->getType())) {
                $this->logger->debug('The Attestation Statement is anonymous.');
                $this->checkCertificateChain($attestationStatement, null);

                return;
            }
            $this->logger->debug('Anonymization required. AAGUID and Attestation Statement changed.', [
                'aaguid' => $aaguid,
                'AttestationStatement' => $attestationStatement,
            ]);
            $attestedCredentialData->setAaguid(
                \Akeeba\Passwordless\Ramsey\Uuid\Uuid::fromString('00000000-0000-0000-0000-000000000000')
            );
            $attestationObject->setAttStmt(\Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement::createNone('none', [], new \Akeeba\Passwordless\Webauthn\TrustPath\EmptyTrustPath()));

            return;
        }
        if (\Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement::TYPE_NONE === $attestationStatement->getType()) {
            $this->logger->debug('No attestation returned.');
            //No attestation is returned. We shall ensure that the AAGUID is a null one.
            if ('00000000-0000-0000-0000-000000000000' !== $aaguid) {
                $this->logger->debug('Anonymization required. AAGUID and Attestation Statement changed.', [
                    'aaguid' => $aaguid,
                    'AttestationStatement' => $attestationStatement,
                ]);
                $attestedCredentialData->setAaguid(
                    \Akeeba\Passwordless\Ramsey\Uuid\Uuid::fromString('00000000-0000-0000-0000-000000000000')
                );

                return;
            }

            return;
        }

        //The MDS Repository is mandatory here
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::notNull($this->metadataStatementRepository, 'The Metadata Statement Repository is mandatory when requesting attestation objects.');
        $metadataStatement = $this->metadataStatementRepository->findOneByAAGUID($aaguid);

        // We check the last status report
        $this->checkStatusReport(null === $metadataStatement ? [] : $metadataStatement->getStatusReports());

        // We check the certificate chain (if any)
        $this->checkCertificateChain($attestationStatement, $metadataStatement);

        // If no Attestation Statement has been returned or if null AAGUID (=00000000-0000-0000-0000-000000000000)
        // => nothing to check
        if ('00000000-0000-0000-0000-000000000000' === $aaguid || \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement::TYPE_NONE === $attestationStatement->getType()) {
            return;
        }

        // At this point, the Metadata Statement is mandatory
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::notNull($metadataStatement, \Akeeba\Passwordless\Safe\sprintf('The Metadata Statement for the AAGUID "%s" is missing', $aaguid));

        // Check Attestation Type is allowed
        if (0 !== count($metadataStatement->getAttestationTypes())) {
            $type = $this->getAttestationType($attestationStatement);
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::inArray($type, $metadataStatement->getAttestationTypes(), 'Invalid attestation statement. The attestation type is not allowed for this authenticator');
        }
    }

    /**
     * @param StatusReport[] $statusReports
     */
    private function checkStatusReport(array $statusReports): void
    {
        if (0 !== count($statusReports)) {
            $lastStatusReport = end($statusReports);
            if ($lastStatusReport->isCompromised()) {
                throw new LogicException('The authenticator is compromised and cannot be used');
            }
        }
    }

    private function createPublicKeyCredentialSource(string $credentialId, \Akeeba\Passwordless\Webauthn\AttestedCredentialData $attestedCredentialData, \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObject $attestationObject, string $userHandle): \Akeeba\Passwordless\Webauthn\PublicKeyCredentialSource
    {
        return new \Akeeba\Passwordless\Webauthn\PublicKeyCredentialSource(
            $credentialId,
            \Akeeba\Passwordless\Webauthn\PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            $attestationObject->getAttStmt()->getType(),
            $attestationObject->getAttStmt()->getTrustPath(),
            $attestedCredentialData->getAaguid(),
            $attestedCredentialData->getCredentialPublicKey(),
            $userHandle,
            $attestationObject->getAuthData()->getSignCount()
        );
    }

    private function getAttestationType(\Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement $attestationStatement): int
    {
        switch ($attestationStatement->getType()) {
            case \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement::TYPE_BASIC:
                return \Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement::ATTESTATION_BASIC_FULL;
            case \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement::TYPE_SELF:
                return \Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement::ATTESTATION_BASIC_SURROGATE;
            case \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement::TYPE_ATTCA:
                return \Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement::ATTESTATION_ATTCA;
            case \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatement::TYPE_ECDAA:
                return \Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement::ATTESTATION_ECDAA;
            default:
                throw new InvalidArgumentException('Invalid attestation type');
        }
    }

    private function getFacetId(string $rpId, \Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs $authenticationExtensionsClientInputs, ?\Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs $authenticationExtensionsClientOutputs): string
    {
        if (null === $authenticationExtensionsClientOutputs || !$authenticationExtensionsClientInputs->has('appid') || !$authenticationExtensionsClientOutputs->has('appid')) {
            return $rpId;
        }
        $appId = $authenticationExtensionsClientInputs->get('appid')->value();
        $wasUsed = $authenticationExtensionsClientOutputs->get('appid')->value();
        if (!is_string($appId) || true !== $wasUsed) {
            return $rpId;
        }

        return $appId;
    }
}
