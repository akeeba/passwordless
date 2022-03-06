<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Joomla\Plugin\System\Passwordless\Credential;

// Protect from unauthorized access
defined('_JEXEC') or die();

use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;
use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Mac\HS384;
use Cose\Algorithm\Mac\HS512;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA;
use Cose\Algorithm\Signature\EdDSA;
use Cose\Algorithm\Signature\RSA;
use Cose\Algorithms;
use Exception;
use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Crypt\Crypt;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\Session\Session;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\ServerRequestFactory;
use RuntimeException;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;
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
use const Joomla\Plugin\System\Passwordless\Helper\JPATH_BASE;

/**
 * Helper class to aid in credentials creation (link an authenticator to a user account)
 *
 * @since   1.0.0
 */
abstract class Authentication
{
	/**
	 * Create a public key for credentials creation. The result is a JSON string which can be used in Javascript code
	 * with navigator.credentials.create().
	 *
	 * @param   User  $user  The Joomla user to create the public key for
	 *
	 * @return  string
	 *
	 * @since   1.0.0
	 */
	public static function createPublicKey(User $user): string
	{
		try
		{
			$app = Factory::getApplication();
		}
		catch (Exception $e)
		{
			return '';
		}

		$siteName = $app->get('sitename');

		// Credentials repository
		$repository = new Repository();

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
			// RSASSA-PKCS1-v1_5 (RFC8017 article 8.1) fallback, only used by Windows Hello
			new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_RS512),
			new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_RS384),
			new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_RS256),
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

		// Authenticator Selection Criteria (we used default values)
		$authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria(
			AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
			false,
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
		/** @var Session $session */
		$session = $app->getSession();
		$session->set('plg_system_passwordless.publicKeyCredentialCreationOptions', base64_encode(serialize($publicKeyCredentialCreationOptions)));
		$session->set('plg_system_passwordless.registration_user_id', $user->id);

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
		/** @var CMSApplication $app */
		$app     = Factory::getApplication();
		$session = $app->getSession();

		// Retrieve the PublicKeyCredentialCreationOptions object created earlier and perform sanity checks
		$encodedOptions = $session->get('plg_system_passwordless.publicKeyCredentialCreationOptions', null);

		if (empty($encodedOptions))
		{
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_NO_PK'));
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
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_NO_PK'));
		}

		// Retrieve the stored user ID and make sure it's the same one in the request.
		$storedUserId = $session->get('plg_system_passwordless.registration_user_id', 0);
		$myUser       = $app->getIdentity() ?? new User();
		$myUserId     = $myUser->id;

		if (($myUser->guest) || ($myUserId != $storedUserId))
		{
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_USER'));
		}

		// Cose Algorithm Manager
		$coseAlgorithmManager = new Manager();
		if (function_exists('sodium_crypto_sign_seed_keypair'))
		{
			$coseAlgorithmManager->add(new EdDSA\EdDSA());
		}
		$coseAlgorithmManager->add(new ECDSA\ES512());
		$coseAlgorithmManager->add(new ECDSA\ES384());
		$coseAlgorithmManager->add(new ECDSA\ES256());
		$coseAlgorithmManager->add(new RSA\PS512());
		$coseAlgorithmManager->add(new RSA\PS384());
		$coseAlgorithmManager->add(new RSA\PS256());
		$coseAlgorithmManager->add(new HS512());
		$coseAlgorithmManager->add(new HS384());
		$coseAlgorithmManager->add(new HS256());
		$coseAlgorithmManager->add(new RSA\RS512());
		$coseAlgorithmManager->add(new RSA\RS384());
		$coseAlgorithmManager->add(new RSA\RS256());

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
		try
		{
			$attestationStatementSupportManager->add(new AndroidSafetyNetAttestationStatementSupport(\Joomla\CMS\Http\HttpFactory::getHttp(), 'GOOGLE_SAFETYNET_API_KEY', new RequestFactory()));
		}
		catch (\Throwable $e)
		{
			// Suck it.
		}
		$attestationStatementSupportManager->add(new AndroidKeyAttestationStatementSupport($decoder));
		$attestationStatementSupportManager->add(new TPMAttestationStatementSupport());
		$attestationStatementSupportManager->add(new PackedAttestationStatementSupport($decoder, $coseAlgorithmManager));

		// Attestation Object Loader
		$attestationObjectLoader = new AttestationObjectLoader($attestationStatementSupportManager, $decoder);

		// Public Key Credential Loader
		$publicKeyCredentialLoader = new PublicKeyCredentialLoader($attestationObjectLoader, $decoder);

		// Credential Repository
		$credentialRepository = new Repository();

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
		$publicKeyCredentialSource = $authenticatorAttestationResponseValidator->check($response, $publicKeyCredentialCreationOptions, $request);

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
