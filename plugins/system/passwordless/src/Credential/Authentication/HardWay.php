<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

/**
 * @package     Joomla\Plugin\System\Passwordless\Credential\Authentication
 * @subpackage
 *
 * @copyright   A copyright
 * @license     A "Slug" license name e.g. GPL2
 */

namespace Joomla\Plugin\System\Passwordless\Credential\Authentication;

use Akeeba\Passwordless\CBOR\Decoder;
use Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManager;
use Akeeba\Passwordless\CBOR\Tag\TagObjectManager;
use Akeeba\Passwordless\Cose\Algorithm\Manager;
use Akeeba\Passwordless\Cose\Algorithm\Signature\ECDSA;
use Akeeba\Passwordless\Cose\Algorithm\Signature\EdDSA;
use Akeeba\Passwordless\Cose\Algorithm\Signature\RSA;
use Akeeba\Passwordless\Cose\Algorithms;
use Akeeba\Passwordless\Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationObjectLoader;
use Akeeba\Passwordless\Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Akeeba\Passwordless\Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Akeeba\Passwordless\Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Akeeba\Passwordless\Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Akeeba\Passwordless\Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Akeeba\Passwordless\Webauthn\AuthenticatorAssertionResponse;
use Akeeba\Passwordless\Webauthn\AuthenticatorAssertionResponseValidator;
use Akeeba\Passwordless\Webauthn\AuthenticatorAttestationResponse;
use Akeeba\Passwordless\Webauthn\AuthenticatorAttestationResponseValidator;
use Akeeba\Passwordless\Webauthn\AuthenticatorSelectionCriteria;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialCreationOptions;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialLoader;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialParameters;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialRequestOptions;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialRpEntity;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialSource;
use Akeeba\Passwordless\Webauthn\TokenBinding\TokenBindingNotSupportedHandler;
use Exception;
use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Factory;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\Session\SessionInterface;
use Laminas\Diactoros\ServerRequestFactory;
use RuntimeException;

/**
 * Authentication helper adapter implemented in what the library describes as the "hard way". Challenge accepted.
 *
 * @since  1.0.0
 */
class HardWay extends AbstractAuthentication
{
	/**
	 * @inheritDoc
	 */
	public function getPubKeyCreationOptions(User $user): PublicKeyCredentialCreationOptions
	{
		/** @var CMSApplication $app */
		$app      = Factory::getApplication();
		$siteName = $app->get('sitename');

		// Credentials repository
		$repository = $this->getCredentialsRepository();

		// Relaying Party -- Our site
		$rpEntity = new PublicKeyCredentialRpEntity(
			$siteName ?? 'Joomla! Site',
			Uri::getInstance()->toString(['host']),
			$this->getSiteIcon() ?? ''
		);

		// User Entity
		$userEntity = $this->getUserEntity($user);

		// Challenge
		$challenge = random_bytes(32);

		// Public Key Credential Parameters
		$publicKeyCredentialParametersList = [
			// Prefer ECDSA (keys based on Elliptic Curve Cryptography with NIST P-521, P-384 or P-256)
			new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES512),
			new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES384),
			new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES256),
			// Fall back to RSASSA-PSS when ECC is not available. Minimal storage for resident keys available for these.
			new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_PS512),
			new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_PS384),
			new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_PS256),
			// Shared secret w/ HKDF and SHA-512
			new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_DIRECT_HKDF_SHA_512),
			new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_DIRECT_HKDF_SHA_256),
			// Shared secret w/ AES-MAC 256-bit key
			new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_DIRECT_HKDF_AES_256),
		];

		// If libsodium is enabled prefer Edwards-curve Digital Signature Algorithm (EdDSA)
		if (function_exists('sodium_crypto_sign_seed_keypair'))
		{
			array_unshift($publicKeyCredentialParametersList, new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_EdDSA));
		}

		// Timeout: 60 seconds (given in milliseconds)
		$timeout = 60000;

		// Devices to exclude (already set up authenticators)
		$excludedPublicKeyDescriptors = $this->getPubKeyDescriptorsForUser($user);

		$requireResidentKey      = false;
		$authenticatorAttachment = AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE;

		// Authenticator Selection Criteria (we used default values)
		$authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria(
			$authenticatorAttachment,
			$requireResidentKey,
			AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED
		);

		// Extensions (not yet supported by the library)
		$extensions = new AuthenticationExtensionsClientInputs();

		// Attestation preference
		$attestationPreference = PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE;

		// Public key credential creation options
		return new PublicKeyCredentialCreationOptions(
			$rpEntity,
			$userEntity,
			$challenge,
			$publicKeyCredentialParametersList,
			$timeout,
			$excludedPublicKeyDescriptors,
			$authenticatorSelectionCriteria,
			$attestationPreference,
			$extensions
		);
	}

	/**
	 * @inheritDoc
	 */
	public function validateAttestationResponse(string $data, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions): ?PublicKeyCredentialSource
	{
		// Cose Algorithm Manager
		$coseAlgorithmManager = new Manager();
		$coseAlgorithmManager->add(new ECDSA\ES256());
		$coseAlgorithmManager->add(new ECDSA\ES512());
		$coseAlgorithmManager->add(new EdDSA\EdDSA());
		$coseAlgorithmManager->add(new RSA\RS1());
		$coseAlgorithmManager->add(new RSA\RS256());
		$coseAlgorithmManager->add(new RSA\RS512());

		// Create a CBOR Decoder object
		$otherObjectManager = new OtherObjectManager();
		$tagObjectManager   = new TagObjectManager();
		$decoder            = new Decoder($tagObjectManager, $otherObjectManager);

		// The token binding handler
		$tokenBindingHandler = new TokenBindingNotSupportedHandler();

		// Attestation Statement Support Manager
		$attestationStatementSupportManager = new AttestationStatementSupportManager();
		$attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
		$attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport());
		$attestationStatementSupportManager->add(new AndroidKeyAttestationStatementSupport());
		$attestationStatementSupportManager->add(new TPMAttestationStatementSupport());
		$attestationStatementSupportManager->add(new PackedAttestationStatementSupport($coseAlgorithmManager));

		// Attestation Object Loader
		$attestationObjectLoader = new AttestationObjectLoader($attestationStatementSupportManager);

		// Public Key Credential Loader
		$publicKeyCredentialLoader = new PublicKeyCredentialLoader($attestationObjectLoader);


		// Credential Repository
		$credentialRepository = $this->getCredentialsRepository();

		// Extension output checker handler
		$extensionOutputCheckerHandler = new ExtensionOutputCheckerHandler();

		// Authenticator Attestation Response Validator
		$authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
			$attestationStatementSupportManager,
			$credentialRepository,
			$tokenBindingHandler,
			$extensionOutputCheckerHandler
		);

		// Any Throwable from this point will bubble up to the GUI

		// We init the PSR-7 request object using Diactoros
		$request = ServerRequestFactory::fromGlobals();

		// Load the data
		$publicKeyCredential = $publicKeyCredentialLoader->load(base64_decode($data));
		$response            = $publicKeyCredential->getResponse();

		// Check if the response is an Authenticator Attestation Response
		if (!$response instanceof AuthenticatorAttestationResponse)
		{
			throw new RuntimeException('Not an authenticator attestation response');
		}

		// Check the response against the request
		$authenticatorAttestationResponseValidator->check($response, $publicKeyCredentialCreationOptions, $request);

		/**
		 * Everything is OK here. You can get the Public Key Credential Source. This object should be persisted using
		 * the Public Key Credential Source repository.
		 */
		return $authenticatorAttestationResponseValidator->check($response, $publicKeyCredentialCreationOptions, $request);
	}

	/**
	 * @inheritDoc
	 */
	public function getPubkeyRequestOptions(User $user): ?PublicKeyCredentialRequestOptions
	{
		// Create a WebAuthn challenge and set it in the session
		$repository = $this->getCredentialsRepository();

		// Load the saved credentials into an array of PublicKeyCredentialDescriptor objects
		try
		{
			$userEntity  = $this->getUserEntity($user);
			$credentials = $repository->findAllForUserEntity($userEntity);
		}
		catch (Exception $e)
		{
			$credentials = null;
		}

		// No stored credentials?
		if (empty($credentials))
		{
			return null;
		}

		$registeredPublicKeyCredentialDescriptors = $this->getPubKeyDescriptorsForUser($user);

		$challenge = random_bytes(32);

		// Extensions
		$extensions = new AuthenticationExtensionsClientInputs;

		// Public Key Credential Request Options
		return new PublicKeyCredentialRequestOptions(
			$challenge,
			60000,
			Uri::getInstance()->toString(['host']),
			$registeredPublicKeyCredentialDescriptors,
			PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
			$extensions
		);
	}

	/**
	 * @inheritDoc
	 */
	public function validateAssertionResponse(string $data, PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions): PublicKeyCredentialSource
	{
		/** @var SessionInterface $session */
		$session = Factory::getApplication()->getSession();
		$userId  = $session->get('plg_loginguard_webauthn.userId', null);

		// Create a credentials repository
		$credentialRepository = $this->getCredentialsRepository();

		// Cose Algorithm Manager
		$coseAlgorithmManager = new Manager;
		$coseAlgorithmManager->add(new ECDSA\ES256);
		$coseAlgorithmManager->add(new ECDSA\ES512);
		$coseAlgorithmManager->add(new EdDSA\EdDSA);
		$coseAlgorithmManager->add(new RSA\RS1);
		$coseAlgorithmManager->add(new RSA\RS256);
		$coseAlgorithmManager->add(new RSA\RS512);

		// Attestation Statement Support Manager
		$attestationStatementSupportManager = new AttestationStatementSupportManager();
		$attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
		$attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport());
		$attestationStatementSupportManager->add(new AndroidKeyAttestationStatementSupport());
		$attestationStatementSupportManager->add(new TPMAttestationStatementSupport);
		$attestationStatementSupportManager->add(new PackedAttestationStatementSupport($coseAlgorithmManager));

		// Attestation Object Loader
		$attestationObjectLoader = new AttestationObjectLoader($attestationStatementSupportManager);

		// Public Key Credential Loader
		$publicKeyCredentialLoader = new PublicKeyCredentialLoader($attestationObjectLoader);

		// The token binding handler
		$tokenBindingHandler = new TokenBindingNotSupportedHandler();

		// Extension Output Checker Handler
		$extensionOutputCheckerHandler = new ExtensionOutputCheckerHandler;

		// Authenticator Assertion Response Validator
		$authenticatorAssertionResponseValidator = new AuthenticatorAssertionResponseValidator(
			$credentialRepository,
			$tokenBindingHandler,
			$extensionOutputCheckerHandler,
			$coseAlgorithmManager
		);

		// We init the Symfony Request object
		$request = ServerRequestFactory::fromGlobals();

		// Load the data
		$publicKeyCredential = $publicKeyCredentialLoader->load($data);
		$response            = $publicKeyCredential->getResponse();

		// Check if the response is an Authenticator Assertion Response
		if (!$response instanceof AuthenticatorAssertionResponse)
		{
			throw new RuntimeException('Not an authenticator assertion response');
		}

		/** @var AuthenticatorAssertionResponse $authenticatorAssertionResponse */
		$authenticatorAssertionResponse = $publicKeyCredential->getResponse();

		return $authenticatorAssertionResponseValidator->check(
			$publicKeyCredential->getRawId(),
			$authenticatorAssertionResponse,
			$publicKeyCredentialRequestOptions,
			$request,
			$credentialRepository->getHandleFromUserId($userId)
		);
	}


}