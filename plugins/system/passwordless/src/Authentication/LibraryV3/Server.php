<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2023 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Plugin\System\Passwordless\Authentication\LibraryV3;

defined('_JEXEC') or die();

use Assert\Assertion;
use Cose\Algorithm\Algorithm;
use Cose\Algorithm\ManagerFactory;
use Cose\Algorithm\Signature\ECDSA;
use Cose\Algorithm\Signature\EdDSA;
use Cose\Algorithm\Signature\RSA;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;

/**
 * Customised WebAuthn server object.
 *
 * We had to fork the server object from the WebAuthn server package to address an issue with PHP 8.
 *
 * We are currently using an older version of the WebAuthn library (2.x) which was written before
 * PHP 8 was developed. We cannot upgrade the WebAuthn library to a newer major version because of
 * Joomla's Semantic Versioning promise.
 *
 * The FidoU2FAttestationStatementSupport and AndroidKeyAttestationStatementSupport classes force
 * an assertion on the result of the openssl_pkey_get_public() function, assuming it will return a
 * resource. However, starting with PHP 8.0 this function returns an OpenSSLAsymmetricKey object
 * and the assertion fails. As a result, you cannot use Android or FIDO U2F keys with WebAuthn.
 *
 * The assertion check is in a private method, therefore we have to fork both attestation support
 * classes to change the assertion. The assertion takes place through a third party library we
 * cannot (and should not!) modify.
 *
 * The assertions objects, however, are injected to the attestation support manager in a private
 * method of the Server object. Because literally everything in this class is private we have no
 * option than to fork the entire class to apply our two forked attestation support classes.
 *
 * This is marked as deprecated because we'll be able to upgrade the WebAuthn library on Joomla 5.
 *
 * @since   2.0.0
 */
class Server extends \Webauthn\Server
{
	/**
	 * @var   integer
	 * @since 2.0.0
	 */
	public $timeout = 60000;

	/**
	 * @var   integer
	 * @since 2.0.0
	 */
	public $challengeSize = 32;

	/**
	 * @var   PublicKeyCredentialRpEntity
	 * @since 2.0.0
	 */
	private $rpEntity;

	/**
	 * @var   ManagerFactory
	 * @since 2.0.0
	 */
	private $coseAlgorithmManagerFactory;

	/**
	 * @var   PublicKeyCredentialSourceRepository
	 * @since 2.0.0
	 */
	private $publicKeyCredentialSourceRepository;

	/**
	 * @var   TokenBindingNotSupportedHandler
	 * @since 2.0.0
	 */
	private $tokenBindingHandler;

	/**
	 * @var   ExtensionOutputCheckerHandler
	 * @since 2.0.0
	 */
	private $extensionOutputCheckerHandler;

	/**
	 * @var   string[]
	 * @since 2.0.0
	 */
	private $selectedAlgorithms;

	/**
	 * @var   ClientInterface
	 * @since 2.0.0
	 */
	private $httpClient;

	/**
	 * @var   string
	 * @since 2.0.0
	 */
	private $googleApiKey;

	/**
	 * @var   RequestFactoryInterface
	 * @since 2.0.0
	 */
	private $requestFactory;

	/**
	 * Overridden constructor.
	 *
	 * @param   PublicKeyCredentialRpEntity          $relayingParty                        Obvious
	 * @param   PublicKeyCredentialSourceRepository  $publicKeyCredentialSourceRepository  Obvious
	 *
	 * @since        2.0.0
	 * @noinspection PhpMissingParentConstructorInspection
	 */
	public function __construct(
		PublicKeyCredentialRpEntity         $relayingParty,
		PublicKeyCredentialSourceRepository $publicKeyCredentialSourceRepository
	)
	{
		$this->rpEntity = $relayingParty;

		$this->coseAlgorithmManagerFactory = new ManagerFactory();
		$this->coseAlgorithmManagerFactory->add('RS1', new RSA\RS1());
		$this->coseAlgorithmManagerFactory->add('RS256', new RSA\RS256());
		$this->coseAlgorithmManagerFactory->add('RS384', new RSA\RS384());
		$this->coseAlgorithmManagerFactory->add('RS512', new RSA\RS512());
		$this->coseAlgorithmManagerFactory->add('PS256', new RSA\PS256());
		$this->coseAlgorithmManagerFactory->add('PS384', new RSA\PS384());
		$this->coseAlgorithmManagerFactory->add('PS512', new RSA\PS512());
		$this->coseAlgorithmManagerFactory->add('ES256', new ECDSA\ES256());
		$this->coseAlgorithmManagerFactory->add('ES256K', new ECDSA\ES256K());
		$this->coseAlgorithmManagerFactory->add('ES384', new ECDSA\ES384());
		$this->coseAlgorithmManagerFactory->add('ES512', new ECDSA\ES512());
		$this->coseAlgorithmManagerFactory->add('Ed25519', new EdDSA\Ed25519());

		$this->selectedAlgorithms                  = ['RS256', 'RS512', 'PS256', 'PS512', 'ES256', 'ES512', 'Ed25519'];
		$this->publicKeyCredentialSourceRepository = $publicKeyCredentialSourceRepository;
		$this->tokenBindingHandler                 = new TokenBindingNotSupportedHandler();
		$this->extensionOutputCheckerHandler       = new ExtensionOutputCheckerHandler();
	}

	/**
	 * @param   string[]  $selectedAlgorithms  Obvious
	 *
	 * @return  void
	 * @since   2.0.0
	 */
	public function setSelectedAlgorithms(array $selectedAlgorithms): void
	{
		$this->selectedAlgorithms = $selectedAlgorithms;
	}

	/**
	 * @param   TokenBindingNotSupportedHandler  $tokenBindingHandler  Obvious
	 *
	 * @return  void
	 * @since   2.0.0
	 */
	public function setTokenBindingHandler(TokenBindingNotSupportedHandler $tokenBindingHandler): void
	{
		$this->tokenBindingHandler = $tokenBindingHandler;
	}

	/**
	 * @param   string     $alias      Obvious
	 * @param   Algorithm  $algorithm  Obvious
	 *
	 * @return  void
	 * @since   2.0.0
	 */
	public function addAlgorithm(string $alias, Algorithm $algorithm): void
	{
		$this->coseAlgorithmManagerFactory->add($alias, $algorithm);
		$this->selectedAlgorithms[] = $alias;
		$this->selectedAlgorithms   = array_unique($this->selectedAlgorithms);
	}

	/**
	 * @param   ExtensionOutputCheckerHandler  $extensionOutputCheckerHandler  Obvious
	 *
	 * @return  void
	 * @since   2.0.0
	 */
	public function setExtensionOutputCheckerHandler(ExtensionOutputCheckerHandler $extensionOutputCheckerHandler): void
	{
		$this->extensionOutputCheckerHandler = $extensionOutputCheckerHandler;
	}

	/**
	 * @param   string|null                                $userVerification             Obvious
	 * @param   PublicKeyCredentialDescriptor[]            $allowedPublicKeyDescriptors  Obvious
	 * @param   AuthenticationExtensionsClientInputs|null  $extensions                   Obvious
	 *
	 * @return PublicKeyCredentialRequestOptions
	 * @throws \Exception
	 * @since   2.0.0
	 */
	public function generatePublicKeyCredentialRequestOptions(
		?string                               $userVerification = PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
		array                                 $allowedPublicKeyDescriptors = [],
		?AuthenticationExtensionsClientInputs $extensions = null
	): PublicKeyCredentialRequestOptions
	{
		return new PublicKeyCredentialRequestOptions(
			random_bytes($this->challengeSize),
			$this->timeout,
			$this->rpEntity->getId(),
			$allowedPublicKeyDescriptors,
			$userVerification,
			$extensions ?? new AuthenticationExtensionsClientInputs()
		);
	}

	/**
	 * @param   PublicKeyCredentialUserEntity              $userEntity                    Obvious
	 * @param   string|null                                $attestationMode               Obvious
	 * @param   PublicKeyCredentialDescriptor[]            $excludedPublicKeyDescriptors  Obvious
	 * @param   AuthenticatorSelectionCriteria|null        $criteria                      Obvious
	 * @param   AuthenticationExtensionsClientInputs|null  $extensions                    Obvious
	 *
	 * @return  PublicKeyCredentialCreationOptions
	 * @throws  \Exception
	 * @since   2.0.0
	 */
	public function generatePublicKeyCredentialCreationOptions(
		PublicKeyCredentialUserEntity         $userEntity,
		?string                               $attestationMode = PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
		array                                 $excludedPublicKeyDescriptors = [],
		?AuthenticatorSelectionCriteria       $criteria = null,
		?AuthenticationExtensionsClientInputs $extensions = null
	): PublicKeyCredentialCreationOptions
	{
		$coseAlgorithmManager              = $this->coseAlgorithmManagerFactory->create($this->selectedAlgorithms);
		$publicKeyCredentialParametersList = [];

		foreach ($coseAlgorithmManager->all() as $algorithm)
		{
			$publicKeyCredentialParametersList[] = new PublicKeyCredentialParameters(
				PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
				$algorithm::identifier()
			);
		}

		$criteria   = $criteria ?? new AuthenticatorSelectionCriteria();
		$extensions = $extensions ?? new AuthenticationExtensionsClientInputs();
		$challenge  = random_bytes($this->challengeSize);

		return new PublicKeyCredentialCreationOptions(
			$this->rpEntity,
			$userEntity,
			$challenge,
			$publicKeyCredentialParametersList,
			$this->timeout,
			$excludedPublicKeyDescriptors,
			$criteria,
			$attestationMode,
			$extensions
		);
	}

	/**
	 * @param   string                              $data                                Obvious
	 * @param   PublicKeyCredentialCreationOptions  $publicKeyCredentialCreationOptions  Obvious
	 * @param   ServerRequestInterface              $serverRequest                       Obvious
	 *
	 * @return  PublicKeyCredentialSource
	 * @throws  \Assert\AssertionFailedException
	 * @since   2.0.0
	 */
	public function loadAndCheckAttestationResponse(
		string                             $data,
		PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
		ServerRequestInterface             $serverRequest
	): PublicKeyCredentialSource
	{
		$attestationStatementSupportManager = $this->getAttestationStatementSupportManager();
		$attestationObjectLoader            = new AttestationObjectLoader($attestationStatementSupportManager);
		$publicKeyCredentialLoader          = new PublicKeyCredentialLoader($attestationObjectLoader);

		$publicKeyCredential   = $publicKeyCredentialLoader->load($data);
		$authenticatorResponse = $publicKeyCredential->getResponse();
		Assertion::isInstanceOf($authenticatorResponse, AuthenticatorAttestationResponse::class, 'Not an authenticator attestation response');

		$authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
			$attestationStatementSupportManager,
			$this->publicKeyCredentialSourceRepository,
			$this->tokenBindingHandler,
			$this->extensionOutputCheckerHandler
		);

		return $authenticatorAttestationResponseValidator->check($authenticatorResponse, $publicKeyCredentialCreationOptions, $serverRequest);
	}

	/**
	 * @param   string                              $data                               Obvious
	 * @param   PublicKeyCredentialRequestOptions   $publicKeyCredentialRequestOptions  Obvious
	 * @param   PublicKeyCredentialUserEntity|null  $userEntity                         Obvious
	 * @param   ServerRequestInterface              $serverRequest                      Obvious
	 *
	 * @return  PublicKeyCredentialSource
	 * @throws  \Assert\AssertionFailedException
	 * @since   2.0.0
	 */
	public function loadAndCheckAssertionResponse(
		string                            $data,
		PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
		?PublicKeyCredentialUserEntity    $userEntity,
		ServerRequestInterface            $serverRequest
	): PublicKeyCredentialSource
	{
		$attestationStatementSupportManager = $this->getAttestationStatementSupportManager();
		$attestationObjectLoader            = new AttestationObjectLoader($attestationStatementSupportManager);
		$publicKeyCredentialLoader          = new PublicKeyCredentialLoader($attestationObjectLoader);

		$publicKeyCredential   = $publicKeyCredentialLoader->load($data);
		$authenticatorResponse = $publicKeyCredential->getResponse();
		Assertion::isInstanceOf($authenticatorResponse, AuthenticatorAssertionResponse::class, 'Not an authenticator assertion response');

		$authenticatorAssertionResponseValidator = new AuthenticatorAssertionResponseValidator(
			$this->publicKeyCredentialSourceRepository,
			null,
			$this->tokenBindingHandler,
			$this->extensionOutputCheckerHandler,
			$this->coseAlgorithmManagerFactory->create($this->selectedAlgorithms)
		);

		return $authenticatorAssertionResponseValidator->check(
			$publicKeyCredential->getRawId(),
			$authenticatorResponse,
			$publicKeyCredentialRequestOptions,
			$serverRequest,
			null !== $userEntity ? $userEntity->getId() : null
		);
	}

	/**
	 * @param   ClientInterface          $client          Obvious
	 * @param   string                   $apiKey          Obvious
	 * @param   RequestFactoryInterface  $requestFactory  Obvious
	 *
	 * @return  void
	 * @since   2.0.0
	 */
	public function enforceAndroidSafetyNetVerification(
		ClientInterface         $client,
		string                  $apiKey,
		RequestFactoryInterface $requestFactory
	): void
	{
		$this->httpClient     = $client;
		$this->googleApiKey   = $apiKey;
		$this->requestFactory = $requestFactory;
	}

	/**
	 * @return  AttestationStatementSupportManager
	 * @since   2.0.0
	 */
	private function getAttestationStatementSupportManager(): AttestationStatementSupportManager
	{
		$attestationStatementSupportManager = new AttestationStatementSupportManager();
		$coseAlgorithmManager               = $this->coseAlgorithmManagerFactory->create($this->selectedAlgorithms);

		$attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
		$attestationStatementSupportManager->add(
			new PackedAttestationStatementSupport(
				null,
				$coseAlgorithmManager
			)
		);
		$attestationStatementSupportManager->add(new TPMAttestationStatementSupport);
		$attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport(null));
		$attestationStatementSupportManager->add(new AppleAttestationStatementSupport());
		$attestationStatementSupportManager->add(new AndroidKeyAttestationStatementSupport(null));

		return $attestationStatementSupportManager;
	}
}
