<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Passwordless\Helper;

// Protect from unauthorized access
defined('_JEXEC') or die();

use Akeeba\Passwordless\CredentialRepository;
use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA;
use Cose\Algorithm\Signature\EdDSA;
use Cose\Algorithm\Signature\RSA;
use Cose\Algorithms;
use Exception;
use Joomla\CMS\Crypt\Crypt;
use Joomla\CMS\Factory;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use RuntimeException;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;
use Zend\Diactoros\ServerRequestFactory;

/**
 * Helper class to aid in credentials creation (link an authenticator to a user account)
 *
 * @since   1.0.0
 */
abstract class CredentialsCreation
{
	public const AUTHENTICATOR_U2F = 1;

	public const AUTHENTICATOR_FIDO2 = 2;

	public const AUTHENTICATOR_TPM = 3;

	/**
	 * Create a public key for credentials creation. The result is a JSON string which can be used in Javascript code
	 * with navigator.credentials.create().
	 *
	 * There are three authenticator types for which a Public Key can be created with this method:
	 *
	 * * **U2F** (`AUTHENTICATOR_U2F`). This is the legacy and most compatible method. It instructs the browser to use
	 *   CTAP1 and is compatible with both FIDO1 and FIDO2 keys. The downside is that the resulting key is not stored
	 *   on the authenticator (it is NOT resident), therefore you MUST provide your username to log in with WebAuthn.
	 *   This is the default if nothing else is specified.
	 * * **FIDO2** (`AUTHENTICATOR_FIDO2`). This is the newer and recommended method, as long as the user has a
	 *   compatible authenticator. It uses CTAP2 which is currently only available for FIDO2 keys. It requests that the
	 *   resulting key is resident, i.e. stored with the authenticator. This means that you DO NOT need to provide your
	 *   username when logging in with WebAuthn. The downside is that security keys have a finite storage (typically
	 *   around 20 or so credentials) and resetting them resets not just the stored credentials but ALSO their U2F
	 *   support...
	 * * **TPM** (`AUTHENTICATOR_TPM`). This is a specialization of the FIDO2 type. It requests that CTAP2 is used to
	 *   create a resident key and that the only acceptable authenticator type is platform-specific. Practically, this
	 *   will only work with Touch ID / Face ID (iOS / iPadOS / macOS), fingerprint login (Android) and Windows Hello
	 *   (Windows) but only with the very few browsers which actually support platform-specific authenticators – your
	 *   best bet is Google Chrome.
	 *
	 * Unfortunately, feature detection is not possible at the client side before making the request to link an
	 * authenticator. Therefore you need to call this method with all three authenticator options and let the user
	 * decide which one to use based on the available platform and hardware at hand.
	 *
	 * @param   User  $user               The Joomla user to create the public key for
	 * @param   int   $authenticatorType  The authenticator type you'd like to create a public key for (see above).
	 *
	 * @return  string
	 *
	 * @since   1.0.0
	 */
	public static function createPublicKey(User $user, int $authenticatorType = self::AUTHENTICATOR_U2F): string
	{
		try
		{
			$siteName = Joomla::getConfig()->get('sitename');
		}
		catch (Exception $e)
		{
			$siteName = 'Joomla! Site';
		}

		// Credentials repository
		$repository = new CredentialRepository();

		// Relaying Party -- Our site
		$rpEntity = new PublicKeyCredentialRpEntity(
			$siteName,
			Uri::getInstance()->toString(['host']),
			self::getSiteIcon()
		);

		// User Entity
		$userEntity = new PublicKeyCredentialUserEntity(
			$user->username,
			$repository->getHandleFromUserId($user->id),
			$user->name,
			self::getAvatar($user, 64)
		);

		// Challenge
		try
		{
			$challenge = random_bytes(32);
		}
		catch (Exception $e)
		{
			$challenge = Crypt::genRandomBytes(32);
		}

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
		$excludedPublicKeyDescriptors = [];
		$records                      = $repository->findAllForUserEntity($userEntity);

		/** @var PublicKeyCredentialSource $record */
		foreach ($records as $record)
		{
			$excludedPublicKeyDescriptors[] = new PublicKeyCredentialDescriptor($record->getType(), $record->getCredentialPublicKey());
		}

		$requireResidentKey      = $authenticatorType == self::AUTHENTICATOR_U2F ? false : true;
		$authenticatorAttachment = $authenticatorType == self::AUTHENTICATOR_TPM ? AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM : AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE;

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
		$publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
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

		// Save data in the session
		Joomla::setSessionVar('publicKeyCredentialCreationOptions', base64_encode(serialize($publicKeyCredentialCreationOptions)), 'plg_system_passwordless');
		Joomla::setSessionVar('registration_user_id', $user->id, 'plg_system_passwordless');

		return json_encode($publicKeyCredentialCreationOptions, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	}

	/**
	 * Validate the authentication data returned by the device and return the public key credential source on success.
	 *
	 * An exception will be returned on error. Also, under very rare conditions, you may receive NULL instead of
	 * a PublicKeyCredentialSource object which means that something was off in the returned data from the browser.
	 *
	 * @param   string  $data  The JSON-encoded data returned by the browser during the authentication flow
	 *
	 * @return  PublicKeyCredentialSource|null
	 *
	 * @since   1.0.0
	 */
	public static function validateAuthenticationData(string $data): ?PublicKeyCredentialSource
	{
		// Retrieve the PublicKeyCredentialCreationOptions object created earlier and perform sanity checks
		$encodedOptions = Joomla::getSessionVar('publicKeyCredentialCreationOptions', null, 'plg_system_passwordless');

		if (empty($encodedOptions))
		{
			throw new RuntimeException(Joomla::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_NO_PK'));
		}

		try
		{
			$publicKeyCredentialCreationOptions = unserialize(base64_decode($encodedOptions));
		}
		catch (Exception $e)
		{
			$publicKeyCredentialCreationOptions = null;
		}

		if (!is_object($publicKeyCredentialCreationOptions) || !($publicKeyCredentialCreationOptions instanceof PublicKeyCredentialCreationOptions))
		{
			throw new RuntimeException(Joomla::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_NO_PK'));
		}

		// Retrieve the stored user ID and make sure it's the same one in the request.
		$storedUserId = Joomla::getSessionVar('registration_user_id', 0, 'plg_system_passwordless');

		try
		{
			$myUser = Joomla::getUser();
		}
		catch (Exception $e)
		{
			$dummyUserId = 0;
			$myUser      = Joomla::getUser($dummyUserId);
		}

		$myUserId = $myUser->id;

		if (($myUser->guest) || ($myUserId != $storedUserId))
		{
			throw new RuntimeException(Joomla::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_USER'));
		}

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
		$attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport($decoder));
		//$attestationStatementSupportManager->add(new AndroidSafetyNetAttestationStatementSupport(HttpFactory::getHttp(), 'GOOGLE_SAFETYNET_API_KEY', new RequestFactory()));
		$attestationStatementSupportManager->add(new AndroidKeyAttestationStatementSupport($decoder));
		$attestationStatementSupportManager->add(new TPMAttestationStatementSupport());
		$attestationStatementSupportManager->add(new PackedAttestationStatementSupport($decoder, $coseAlgorithmManager));

		// Attestation Object Loader
		$attestationObjectLoader = new AttestationObjectLoader($attestationStatementSupportManager, $decoder);

		// Public Key Credential Loader
		$publicKeyCredentialLoader = new PublicKeyCredentialLoader($attestationObjectLoader, $decoder);

		// Credential Repository
		$credentialRepository = new CredentialRepository();

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
		$publicKeyCredentialSource = PublicKeyCredentialSource::createFromPublicKeyCredential(
			$publicKeyCredential,
			$publicKeyCredentialCreationOptions->getUser()->getId()
		);

		return $publicKeyCredentialSource;
	}

	/**
	 * Get the user's avatar (through Gravatar)
	 *
	 * @param   User  $user  The Joomla user object
	 * @param   int   $size  The dimensions of the image to fetch (default: 64 pixels)
	 *
	 * @return  string  The URL to the user's avatar
	 *
	 * @since   1.0.0
	 */
	public static function getAvatar(User $user, int $size = 64)
	{
		$scheme    = Uri::getInstance()->getScheme();
		$subdomain = ($scheme == 'https') ? 'secure' : 'www';

		return sprintf('%s://%s.gravatar.com/avatar/%s.jpg?s=%u&d=mm', $scheme, $subdomain, md5($user->email), $size);
	}

	/**
	 * Try to find the site's favicon in the site's root, images, media, templates or current template directory.
	 *
	 * @return  string|null
	 *
	 * @since   1.0.0
	 */
	protected static function getSiteIcon(): ?string
	{
		$filenames = [
			'apple-touch-icon.png',
			'apple_touch_icon.png',
			'favicon.ico',
			'favicon.png',
			'favicon.gif',
			'favicon.bmp',
			'favicon.jpg',
			'favicon.svg',
		];

		try
		{
			$paths = [
				'/',
				'/images/',
				'/media/',
				'/templates/',
				'/templates/' . Factory::getApplication()->getTemplate(),
			];
		}
		catch (Exception $e)
		{
			return null;
		}

		foreach ($paths as $path)
		{
			foreach ($filenames as $filename)
			{
				$relFile  = $path . $filename;
				$filePath = JPATH_BASE . $relFile;

				if (is_file($filePath))
				{
					break 2;
				}

				$relFile = null;
			}
		}

		if (is_null($relFile))
		{
			return null;
		}

		return rtrim(Uri::base(), '/') . '/' . ltrim($relFile, '/');
	}
}
