<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Joomla\Plugin\System\Passwordless\Credential;

// Protect from unauthorized access
defined('_JEXEC') or die();

use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Akeeba\Passwordless\Webauthn\AuthenticatorSelectionCriteria;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialCreationOptions;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialDescriptor;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialRequestOptions;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialRpEntity;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialSource;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialUserEntity;
use Akeeba\Passwordless\Webauthn\Server;
use Exception;
use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\Session\Session;
use Laminas\Diactoros\ServerRequestFactory;
use RuntimeException;

/**
 * Helper class to aid in credentials creation (link an authenticator to a user account)
 *
 * @since   1.0.0
 */
abstract class Authentication
{
	/**
	 * The credentials repository
	 *
	 * @var   CredentialsRepository
	 * @since 1.0.0
	 */
	private static $credentialsRepository;

	/**
	 * Generate the public key creation options.
	 *
	 * This is used for the first step of attestation (key registration).
	 *
	 * The PK creation options and the user ID are stored in the session.
	 *
	 * @param   User  $user  The Joomla user to create the public key for
	 *
	 * @return  PublicKeyCredentialCreationOptions
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	public static function getPubKeyCreationOptions(User $user): PublicKeyCredentialCreationOptions
	{
		$server                             = self::getWebauthnServer();
		$publicKeyCredentialCreationOptions = $server->generatePublicKeyCredentialCreationOptions(
			self::getUserEntity($user),
			PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
			self::getPubKeyDescriptorsForUser($user),
			new AuthenticatorSelectionCriteria(
				AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
				false,
				AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED
			),
			new AuthenticationExtensionsClientInputs()
		);

		// Save data in the session
		$app = Factory::getApplication();
		/** @var Session $session */
		$session = $app->getSession();
		$session->set('plg_system_passwordless.publicKeyCredentialCreationOptions', base64_encode(serialize($publicKeyCredentialCreationOptions)));
		$session->set('plg_system_passwordless.registration_user_id', $user->id);

		return $publicKeyCredentialCreationOptions;
	}

	/**
	 * Get the public key request options.
	 *
	 * This is used in the first step of the assertion (login) flow.
	 *
	 * @param   User  $user
	 *
	 * @return  PublicKeyCredentialRequestOptions
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	public static function getPubkeyRequestOptions(User $user): PublicKeyCredentialRequestOptions
	{
		$server = self::getWebauthnServer();

		$publicKeyCredentialRequestOptions = $server->generatePublicKeyCredentialRequestOptions(
			PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
			self::getPubKeyDescriptorsForUser($user)
		);

		// Save in session. This is used during the verification stage to prevent replay attacks.
		Factory::getApplication()->getSession()
			->set('plg_system_passwordless.publicKeyCredentialRequestOptions', base64_encode(serialize($publicKeyCredentialRequestOptions)));

		return $publicKeyCredentialRequestOptions;
	}

	public static function validateAssertionResponse(string $data): PublicKeyCredentialSource
	{
		$data = base64_decode($data);

		if (empty($data))
		{
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
		}

		$server                 = self::getWebauthnServer();
		$pubKeyCredentialSource = $server->loadAndCheckAssertionResponse(
			$data,
			self::getPKCredentialRequestOptions(),
			Factory::getApplication()->getSession()->get('plg_system_passwordless.userHandle', null) ?: null,
			ServerRequestFactory::fromGlobals()
		);

		return $pubKeyCredentialSource;
	}

	/**
	 * Validate the authenticator attestation.
	 *
	 * This is used for the second step of attestation (key registration), when the user has interacted with the
	 * authenticator and we need to validate the legitimacy of its response.
	 *
	 * An exception will be returned on error. Also, under very rare conditions, you may receive NULL instead of
	 * a PublicKeyCredentialSource object which means that something was off in the returned data from the browser.
	 *
	 * @param   string  $data  The base64-encoded data returned by the browser during the attestation ceremony.
	 *
	 * @return  PublicKeyCredentialSource|null
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	public static function validateAttestationResponse(string $data): ?PublicKeyCredentialSource
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

		/** @var PublicKeyCredentialCreationOptions|null $publicKeyCredentialCreationOptions */
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

		$server = self::getWebauthnServer();

		// We init the PSR-7 request object using Diactoros
		$request = ServerRequestFactory::fromGlobals();

		$publicKeyCredentialSource = $server->loadAndCheckAttestationResponse(base64_decode($data), $publicKeyCredentialCreationOptions, $request);

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
	private static function getAvatar(User $user, int $size = 64)
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
	private static function getSiteIcon(): ?string
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

	/**
	 * Get the WebAuthn server oject
	 *
	 * @return  Server
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	private static function getWebauthnServer(): Server
	{
		$app      = Factory::getApplication();
		$siteName = $app->get('sitename');

		// Credentials repository
		$repository = self::getCredentialsRepository();

		// Relaying Party -- Our site
		$rpEntity = new PublicKeyCredentialRpEntity(
			$siteName,
			Uri::getInstance()->toString(['host']),
			self::getSiteIcon()
		);

		$server = new Server($rpEntity, $repository);

		/**
		 * =============================================================================================================
		 * Note about the metadata repository.
		 * =============================================================================================================
		 *
		 * We do not need to implement an MDS repo since we are not asking for the attestation metadata in this plugin.
		 * If you need to use this plugin in a high security environment you need to fork this plugin and do two things:
		 *
		 * 1. Change ATTESTATION_CONVEYANCE_PREFERENCE_NONE to ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT or
		 *    ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT in the getPubKeyCreationOptions() method.
		 * 2. Implement your own Metadata Statement (MDS) repository and set it here, e.g.
		 *    ```php
		 *    $server->setMetadataStatementRepository(new MyMDSRepository());
		 *    ```
		 * The implementation of the MDS repository is considered out-of-scope since you'd need the MDS from the
		 * manufacturer(s) of your authenticator.
		 *
		 * @see https://webauthn-doc.spomky-labs.com/deep-into-the-framework/attestation-and-metadata-statement
		 */

		// Add the Joomla logger to the Server object -- NO! This causes deprecated notices because... Joomla :(
		// $server->setLogger(Log::createDelegatedLogger());

		// Ed25519 is only available with libsodium
		if (!function_exists('sodium_crypto_sign_seed_keypair'))
		{
			$server->setSelectedAlgorithms(['RS256', 'RS512', 'PS256', 'PS512', 'ES256', 'ES512']);
		}

		return $server;
	}

	/**
	 * Get the credentials repository
	 *
	 * @return  CredentialsRepository
	 *
	 * @since   1.0.0
	 */
	private static function getCredentialsRepository(): CredentialsRepository
	{
		if (self::$credentialsRepository !== null)
		{
			return self::$credentialsRepository;
		}

		self::$credentialsRepository = new CredentialsRepository();

		return self::$credentialsRepository;
	}

	/**
	 * Returns a User Entity object given a Joomla user
	 *
	 * @param   User  $user
	 *
	 * @return  PublicKeyCredentialUserEntity
	 *
	 * @since   1.0.0
	 */
	private static function getUserEntity(User $user): PublicKeyCredentialUserEntity
	{
		$repository = self::getCredentialsRepository();

		return new PublicKeyCredentialUserEntity(
			$user->username,
			$repository->getHandleFromUserId($user->id),
			$user->name,
			self::getAvatar($user, 64)
		);
	}

	/**
	 * Returns an array of the PK credential descriptors (registered authenticators) for the given user.
	 *
	 * @param   User  $user
	 *
	 * @return  PublicKeyCredentialDescriptor[]
	 *
	 * @since   1.0.0
	 */
	private static function getPubKeyDescriptorsForUser(User $user): array
	{
		$userEntity  = self::getUserEntity($user);
		$repository  = self::getCredentialsRepository();
		$descriptors = [];
		$records     = $repository->findAllForUserEntity($userEntity);

		foreach ($records as $record)
		{
			$descriptors[] = new PublicKeyCredentialDescriptor($record->getType(), $record->getCredentialPublicKey());
		}

		return $descriptors;
	}

	/**
	 * Retrieve the public key credential request options saved in the session.
	 *
	 * If they do not exist or are corrupt it is a hacking attempt and we politely tell the attacker to go away.
	 *
	 * @return  PublicKeyCredentialRequestOptions
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	private static function getPKCredentialRequestOptions(): PublicKeyCredentialRequestOptions
	{
		$encodedOptions = Factory::getApplication()->getSession()->get('plg_system_passwordless.publicKeyCredentialRequestOptions', null);

		if (empty($encodedOptions))
		{
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
		}

		try
		{
			$publicKeyCredentialCreationOptions = unserialize(base64_decode($encodedOptions));
		}
		catch (Exception $e)
		{
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
		}

		if (!is_object($publicKeyCredentialCreationOptions) ||
			!($publicKeyCredentialCreationOptions instanceof PublicKeyCredentialRequestOptions))
		{
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
		}

		return $publicKeyCredentialCreationOptions;
	}
}
