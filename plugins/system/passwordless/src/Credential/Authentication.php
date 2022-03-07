<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Joomla\Plugin\System\Passwordless\Credential;

// Protect from unauthorized access
defined('_JEXEC') or die();

use Akeeba\Passwordless\Webauthn\PublicKeyCredentialCreationOptions;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialRequestOptions;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialSource;
use Exception;
use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\User\User;
use Joomla\Plugin\System\Passwordless\Credential\Authentication\AuthenticationInterface;
use Joomla\Plugin\System\Passwordless\Credential\Authentication\ServerObject;
use Joomla\Session\Session;
use Joomla\Session\SessionInterface;
use RuntimeException;

/**
 * Helper class to aid in credentials creation (link an authenticator to a user account)
 *
 * I have built it on the adapter pattern to let me test different backend implementations whenever I upgrade the
 * WebAuthn library without getting terminally lost in the details. Only one adapter is ever user.
 *
 * @since   1.0.0
 */
abstract class Authentication
{
	/**
	 * The authentication helper adapter object
	 *
	 * @var   AuthenticationInterface|null
	 * @since 1.0.0
	 */
	private static $adapter;

	/**
	 * The authentication helper adapter class name we will use
	 *
	 * @var   string
	 * @since 1.0.0
	 */
	private static $preferredAdapterClass = ServerObject::class;

	/**
	 * Generate the public key creation options.
	 *
	 * This is used for the first step of attestation (key registration).
	 *
	 * The PK creation options and the user ID are stored in the session.
	 *
	 * @param   User   $user   The Joomla user to create the public key for
	 *
	 * @return  PublicKeyCredentialCreationOptions
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	public static function getPubKeyCreationOptions(User $user): PublicKeyCredentialCreationOptions
	{
		$publicKeyCredentialCreationOptions = (self::getAdapter())->getPubKeyCreationOptions($user);

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
	 * @param   User   $user
	 *
	 * @return  PublicKeyCredentialRequestOptions
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	public static function getPubkeyRequestOptions(User $user): PublicKeyCredentialRequestOptions
	{
		$publicKeyCredentialRequestOptions = (self::getAdapter())->getPubkeyRequestOptions($user);

		// Save in session. This is used during the verification stage to prevent replay attacks.
		Factory::getApplication()->getSession()
			->set('plg_system_passwordless.publicKeyCredentialRequestOptions', base64_encode(serialize($publicKeyCredentialRequestOptions)));

		return $publicKeyCredentialRequestOptions;
	}

	/**
	 * Validate the authenticator assertion.
	 *
	 * This is used in the second step of the assertion (login) flow. The server verifies that the assertion generated
	 * by the authenticator has not been tampered with.
	 *
	 * @param   string   $data
	 *
	 * @return  PublicKeyCredentialSource
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	public static function validateAssertionResponse(string $data): PublicKeyCredentialSource
	{
		/** @var SessionInterface $session */
		$session = Factory::getApplication()->getSession();

		// Make sure the public key credential request options in the session are valid
		$encodedPkOptions                  = $session->get('plg_system_passwordless.publicKeyCredentialRequestOptions', null);
		$serializedOptions                 = base64_decode($encodedPkOptions);
		$publicKeyCredentialRequestOptions = unserialize($serializedOptions);

		if (!is_object($publicKeyCredentialRequestOptions) || empty($publicKeyCredentialRequestOptions) || !($publicKeyCredentialRequestOptions instanceof PublicKeyCredentialRequestOptions))
		{
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
		}

		$data = base64_decode($data);

		if (empty($data))
		{
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
		}

		return (self::getAdapter())->validateAssertionResponse($data, $publicKeyCredentialRequestOptions);
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
	 * @param   string   $data   The base64-encoded data returned by the browser during the attestation ceremony.
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

		return (self::getAdapter())->validateAttestationResponse($data, $publicKeyCredentialCreationOptions);
	}

	private static function getAdapter(): AuthenticationInterface
	{
		if (!empty(self::$adapter))
		{
			return self::$adapter;
		}

		self::$adapter = new self::$preferredAdapterClass;

		return self::$adapter;
	}
}
