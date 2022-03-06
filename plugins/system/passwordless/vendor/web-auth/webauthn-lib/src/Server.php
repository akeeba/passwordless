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
use Akeeba\Passwordless\Cose\Algorithm\Algorithm;
use Akeeba\Passwordless\Cose\Algorithm\ManagerFactory;
use Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA;
use Akeeba\Passwordless\Cose\Algorithm\Signature\EdDSA;
use Akeeba\Passwordless\Cose\Algorithm\Signature\RSA;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Akeeba\Passwordless\Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Akeeba\Passwordless\Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;
use Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObjectLoader;
use Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Akeeba\Passwordless\Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Akeeba\Passwordless\Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Akeeba\Passwordless\Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Akeeba\Passwordless\Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Akeeba\Passwordless\Webauthn\Counter\CounterChecker;
use Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatementRepository;
use Akeeba\Passwordless\Webauthn\TokenBinding\IgnoreTokenBindingHandler;
use Akeeba\Passwordless\Webauthn\TokenBinding\TokenBindingHandler;

class Server
{
    /**
     * @var int
     */
    public $timeout = 60000;

    /**
     * @var int
     */
    public $challengeSize = 32;

    /**
     * @var PublicKeyCredentialRpEntity
     */
    private $rpEntity;

    /**
     * @var ManagerFactory
     */
    private $coseAlgorithmManagerFactory;

    /**
     * @var PublicKeyCredentialSourceRepository
     */
    private $publicKeyCredentialSourceRepository;

    /**
     * @var TokenBindingHandler
     */
    private $tokenBindingHandler;

    /**
     * @var ExtensionOutputCheckerHandler
     */
    private $extensionOutputCheckerHandler;

    /**
     * @var string[]
     */
    private $selectedAlgorithms;

    /**
     * @var MetadataStatementRepository|null
     */
    private $metadataStatementRepository;

    /**
     * @var ClientInterface|null
     */
    private $httpClient;

    /**
     * @var string|null
     */
    private $googleApiKey;

    /**
     * @var RequestFactoryInterface|null
     */
    private $requestFactory;

    /**
     * @var CounterChecker|null
     */
    private $counterChecker;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var string[]
     */
    private $securedRelyingPartyId = [];

    public function __construct(\Akeeba\Passwordless\Webauthn\PublicKeyCredentialRpEntity $relyingParty, \Akeeba\Passwordless\Webauthn\PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository, ?\Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatementRepository $metadataStatementRepository = null)
    {
        if (null !== $metadataStatementRepository) {
            @trigger_error('The argument "metadataStatementRepository" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setMetadataStatementRepository".', E_USER_DEPRECATED);
        }
        $this->rpEntity = $relyingParty;
        $this->logger = new NullLogger();

        $this->coseAlgorithmManagerFactory = new \Akeeba\Passwordless\Cose\Algorithm\ManagerFactory();
        $this->coseAlgorithmManagerFactory->add('RS1', new \Akeeba\Passwordless\Cose\Algorithm\Signature\RSA\RS1());
        $this->coseAlgorithmManagerFactory->add('RS256', new \Akeeba\Passwordless\Cose\Algorithm\Signature\RSA\RS256());
        $this->coseAlgorithmManagerFactory->add('RS384', new \Akeeba\Passwordless\Cose\Algorithm\Signature\RSA\RS384());
        $this->coseAlgorithmManagerFactory->add('RS512', new \Akeeba\Passwordless\Cose\Algorithm\Signature\RSA\RS512());
        $this->coseAlgorithmManagerFactory->add('PS256', new \Akeeba\Passwordless\Cose\Algorithm\Signature\RSA\PS256());
        $this->coseAlgorithmManagerFactory->add('PS384', new \Akeeba\Passwordless\Cose\Algorithm\Signature\RSA\PS384());
        $this->coseAlgorithmManagerFactory->add('PS512', new \Akeeba\Passwordless\Cose\Algorithm\Signature\RSA\PS512());
        $this->coseAlgorithmManagerFactory->add('ES256', new \Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA\ES256());
        $this->coseAlgorithmManagerFactory->add('ES256K', new \Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA\ES256K());
        $this->coseAlgorithmManagerFactory->add('ES384', new \Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA\ES384());
        $this->coseAlgorithmManagerFactory->add('ES512', new \Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA\ES512());
        $this->coseAlgorithmManagerFactory->add('Ed25519', new \Akeeba\Passwordless\Cose\Algorithm\Signature\EdDSA\Ed25519());

        $this->selectedAlgorithms = ['RS256', 'RS512', 'PS256', 'PS512', 'ES256', 'ES512', 'Ed25519'];
        $this->publicKeyCredentialSourceRepository = $publicKeyCredentialSourceRepository;
        $this->tokenBindingHandler = new \Akeeba\Passwordless\Webauthn\TokenBinding\IgnoreTokenBindingHandler();
        $this->extensionOutputCheckerHandler = new \Akeeba\Passwordless\Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler();
        $this->metadataStatementRepository = $metadataStatementRepository;
    }

    public function setMetadataStatementRepository(\Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatementRepository $metadataStatementRepository): self
    {
        $this->metadataStatementRepository = $metadataStatementRepository;

        return $this;
    }

    /**
     * @param string[] $selectedAlgorithms
     */
    public function setSelectedAlgorithms(array $selectedAlgorithms): self
    {
        $this->selectedAlgorithms = $selectedAlgorithms;

        return $this;
    }

    public function setTokenBindingHandler(\Akeeba\Passwordless\Webauthn\TokenBinding\TokenBindingHandler $tokenBindingHandler): self
    {
        $this->tokenBindingHandler = $tokenBindingHandler;

        return $this;
    }

    public function addAlgorithm(string $alias, \Akeeba\Passwordless\Cose\Algorithm\Algorithm $algorithm): self
    {
        $this->coseAlgorithmManagerFactory->add($alias, $algorithm);
        $this->selectedAlgorithms[] = $alias;
        $this->selectedAlgorithms = array_unique($this->selectedAlgorithms);

        return $this;
    }

    public function setExtensionOutputCheckerHandler(\Akeeba\Passwordless\Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler $extensionOutputCheckerHandler): self
    {
        $this->extensionOutputCheckerHandler = $extensionOutputCheckerHandler;

        return $this;
    }

    /**
     * @param string[] $securedRelyingPartyId
     */
    public function setSecuredRelyingPartyId(array $securedRelyingPartyId): self
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::allString($securedRelyingPartyId, 'Invalid list. Shall be a list of strings');
        $this->securedRelyingPartyId = $securedRelyingPartyId;

        return $this;
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $excludedPublicKeyDescriptors
     */
    public function generatePublicKeyCredentialCreationOptions(\Akeeba\Passwordless\Webauthn\PublicKeyCredentialUserEntity $userEntity, ?string $attestationMode = null, array $excludedPublicKeyDescriptors = [], ?\Akeeba\Passwordless\Webauthn\AuthenticatorSelectionCriteria $criteria = null, ?\Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs $extensions = null): \Akeeba\Passwordless\Webauthn\PublicKeyCredentialCreationOptions
    {
        $coseAlgorithmManager = $this->coseAlgorithmManagerFactory->create($this->selectedAlgorithms);
        $publicKeyCredentialParametersList = [];
        foreach ($coseAlgorithmManager->all() as $algorithm) {
            $publicKeyCredentialParametersList[] = new \Akeeba\Passwordless\Webauthn\PublicKeyCredentialParameters(
                \Akeeba\Passwordless\Webauthn\PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $algorithm::identifier()
            );
        }
        $criteria = $criteria ?? new \Akeeba\Passwordless\Webauthn\AuthenticatorSelectionCriteria();
        $extensions = $extensions ?? new \Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs();
        $challenge = random_bytes($this->challengeSize);

        return \Akeeba\Passwordless\Webauthn\PublicKeyCredentialCreationOptions::create(
                $this->rpEntity,
                $userEntity,
                $challenge,
                $publicKeyCredentialParametersList
            )
            ->excludeCredentials($excludedPublicKeyDescriptors)
            ->setAuthenticatorSelection($criteria)
            ->setAttestation($attestationMode ?? \Akeeba\Passwordless\Webauthn\PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE)
            ->setExtensions($extensions)
            ->setTimeout($this->timeout)
        ;
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $allowedPublicKeyDescriptors
     */
    public function generatePublicKeyCredentialRequestOptions(?string $userVerification = null, array $allowedPublicKeyDescriptors = [], ?\Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs $extensions = null): \Akeeba\Passwordless\Webauthn\PublicKeyCredentialRequestOptions
    {
        return \Akeeba\Passwordless\Webauthn\PublicKeyCredentialRequestOptions::create(random_bytes($this->challengeSize))
            ->setRpId($this->rpEntity->getId())
            ->setUserVerification($userVerification ?? \Akeeba\Passwordless\Webauthn\PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED)
            ->allowCredentials($allowedPublicKeyDescriptors)
            ->setTimeout($this->timeout)
            ->setExtensions($extensions ?? new \Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs())
        ;
    }

    public function loadAndCheckAttestationResponse(string $data, \Akeeba\Passwordless\Webauthn\PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions, ServerRequestInterface $serverRequest): \Akeeba\Passwordless\Webauthn\PublicKeyCredentialSource
    {
        $attestationStatementSupportManager = $this->getAttestationStatementSupportManager();
        $attestationObjectLoader = \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObjectLoader::create($attestationStatementSupportManager)
            ->setLogger($this->logger)
        ;
        $publicKeyCredentialLoader = \Akeeba\Passwordless\Webauthn\PublicKeyCredentialLoader::create($attestationObjectLoader)
            ->setLogger($this->logger)
        ;

        $publicKeyCredential = $publicKeyCredentialLoader->load($data);
        $authenticatorResponse = $publicKeyCredential->getResponse();
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isInstanceOf($authenticatorResponse, \Akeeba\Passwordless\Webauthn\AuthenticatorAttestationResponse::class, 'Not an authenticator attestation response');

        $authenticatorAttestationResponseValidator = new \Akeeba\Passwordless\Webauthn\AuthenticatorAttestationResponseValidator(
            $attestationStatementSupportManager,
            $this->publicKeyCredentialSourceRepository,
            $this->tokenBindingHandler,
            $this->extensionOutputCheckerHandler,
            $this->metadataStatementRepository
        );
        $authenticatorAttestationResponseValidator->setLogger($this->logger);

        return $authenticatorAttestationResponseValidator->check($authenticatorResponse, $publicKeyCredentialCreationOptions, $serverRequest, $this->securedRelyingPartyId);
    }

    public function loadAndCheckAssertionResponse(string $data, \Akeeba\Passwordless\Webauthn\PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, ?\Akeeba\Passwordless\Webauthn\PublicKeyCredentialUserEntity $userEntity, ServerRequestInterface $serverRequest): \Akeeba\Passwordless\Webauthn\PublicKeyCredentialSource
    {
        $attestationStatementSupportManager = $this->getAttestationStatementSupportManager();
        $attestationObjectLoader = \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObjectLoader::create($attestationStatementSupportManager)
            ->setLogger($this->logger)
        ;
        $publicKeyCredentialLoader = \Akeeba\Passwordless\Webauthn\PublicKeyCredentialLoader::create($attestationObjectLoader)
            ->setLogger($this->logger)
        ;

        $publicKeyCredential = $publicKeyCredentialLoader->load($data);
        $authenticatorResponse = $publicKeyCredential->getResponse();
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isInstanceOf($authenticatorResponse, \Akeeba\Passwordless\Webauthn\AuthenticatorAssertionResponse::class, 'Not an authenticator assertion response');

        $authenticatorAssertionResponseValidator = new \Akeeba\Passwordless\Webauthn\AuthenticatorAssertionResponseValidator(
            $this->publicKeyCredentialSourceRepository,
            $this->tokenBindingHandler,
            $this->extensionOutputCheckerHandler,
            $this->coseAlgorithmManagerFactory->create($this->selectedAlgorithms),
            $this->counterChecker
        );
        $authenticatorAssertionResponseValidator->setLogger($this->logger);

        return $authenticatorAssertionResponseValidator->check(
            $publicKeyCredential->getRawId(),
            $authenticatorResponse,
            $publicKeyCredentialRequestOptions,
            $serverRequest,
            null !== $userEntity ? $userEntity->getId() : null,
            $this->securedRelyingPartyId
        );
    }

    public function setCounterChecker(\Akeeba\Passwordless\Webauthn\Counter\CounterChecker $counterChecker): self
    {
        $this->counterChecker = $counterChecker;

        return $this;
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    public function enforceAndroidSafetyNetVerification(ClientInterface $client, string $apiKey, RequestFactoryInterface $requestFactory): self
    {
        $this->httpClient = $client;
        $this->googleApiKey = $apiKey;
        $this->requestFactory = $requestFactory;

        return $this;
    }

    private function getAttestationStatementSupportManager(): \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupportManager
    {
        $attestationStatementSupportManager = new \Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupportManager();
        $attestationStatementSupportManager->add(new \Akeeba\Passwordless\Webauthn\AttestationStatement\NoneAttestationStatementSupport());
        $attestationStatementSupportManager->add(new \Akeeba\Passwordless\Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport());
        if (class_exists(RS256::class) && class_exists(JWKFactory::class)) {
            $androidSafetyNetAttestationStatementSupport = new \Akeeba\Passwordless\Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport();
            if (null !== $this->httpClient && null !== $this->googleApiKey && null !== $this->requestFactory) {
                $androidSafetyNetAttestationStatementSupport
                    ->enableApiVerification($this->httpClient, $this->googleApiKey, $this->requestFactory)
                    ->setLeeway(2000)
                    ->setMaxAge(60000)
                ;
            }
            $attestationStatementSupportManager->add($androidSafetyNetAttestationStatementSupport);
        }
        $attestationStatementSupportManager->add(new \Akeeba\Passwordless\Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport());
        $attestationStatementSupportManager->add(new \Akeeba\Passwordless\Webauthn\AttestationStatement\TPMAttestationStatementSupport());
        $coseAlgorithmManager = $this->coseAlgorithmManagerFactory->create($this->selectedAlgorithms);
        $attestationStatementSupportManager->add(new \Akeeba\Passwordless\Webauthn\AttestationStatement\PackedAttestationStatementSupport($coseAlgorithmManager));

        return $attestationStatementSupportManager;
    }
}
