<?php
/*
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2020 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Passwordless\PluginTraits;

// Protect from unauthorized access
defined('_JEXEC') or die();

use Akeeba\Passwordless\CredentialRepository;
use Akeeba\Passwordless\Helper\Joomla;
use Exception;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\UserHelper;
use Throwable;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Ajax handler for akaction=challenge
 *
 * Generates the public key and challenge which is used by the browser when logging in with Webauthn. This is the bit
 * which prevents tampering with the login process and replay attacks.
 */
trait AjaxHandlerChallenge
{
	/**
	 * Returns the public key set for the user and a unique challenge in a Public Key Credential Request encoded as
	 * JSON.
	 *
	 * @return   string  A JSON-encoded object or JSON-encoded false if the username is invalid or no credentials stored
	 *
	 * @throws   Exception
	 */
	public function onAjaxWebauthnChallenge()
	{
		// Initialize objects
		$input = Joomla::getApplication()->input;

		// Retrieve data from the request
		$username  = $input->getUsername('username', '');
		$returnUrl = base64_encode(Joomla::getSessionVar('returnUrl', Uri::current(), 'plg_system_passwordless'));
		$returnUrl = $input->getBase64('returnUrl', $returnUrl);
		$returnUrl = base64_decode($returnUrl);

		// For security reasons the post-login redirection URL must be internal to the site.
		if (!Uri::isInternal($returnUrl))
		{
			// If the URL wasn't internal redirect to the site's root.
			$returnUrl = Uri::base();
		}

		Joomla::setSessionVar('returnUrl', $returnUrl, 'plg_system_passwordless');

		// Get the user_id from the username, if a username was specified at all
		try
		{
			$user_id = empty($username) ? 0 : UserHelper::getUserId($username);
		}
		catch (Exception $e)
		{
			$user_id = 0;
		}

		$registeredPublicKeyCredentialDescriptors = $this->getRegisteredPublicKeyCredentialDescriptors($user_id);

		// Extensions
		$extensions = new AuthenticationExtensionsClientInputs();

		// Public Key Credential Request Options
		$publicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions(
			random_bytes(32),
			60000,
			Uri::getInstance()->toString(['host']),
			$registeredPublicKeyCredentialDescriptors,
			PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
			$extensions
		);

		// Save in session. This is used during the verification stage to prevent replay attacks.
		Joomla::setSessionVar('publicKeyCredentialRequestOptions', base64_encode(serialize($publicKeyCredentialRequestOptions)), 'plg_system_passwordless');

		// Return the JSON encoded data to the caller
		return json_encode($publicKeyCredentialRequestOptions, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	}

	/**
	 * @param   int  $user_id
	 *
	 * @return array
	 */
	private function getRegisteredPublicKeyCredentialDescriptors(int $user_id): array
	{
		$registeredPublicKeyCredentialDescriptors = [];

		if (empty($user_id))
		{
			return $registeredPublicKeyCredentialDescriptors;
		}

		// Load the saved credentials into an array of PublicKeyCredentialDescriptor objects
		try
		{
			$repository  = new CredentialRepository();
			$userEntity  = new PublicKeyCredentialUserEntity('', $repository->getHandleFromUserId($user_id), '');
			$credentials = $repository->findAllForUserEntity($userEntity);
		}
		catch (Exception $e)
		{
			return $registeredPublicKeyCredentialDescriptors;
		}

		// No stored credentials?
		if (empty($credentials))
		{
			return $registeredPublicKeyCredentialDescriptors;
		}

		/** @var PublicKeyCredentialSource $record */
		foreach ($credentials as $record)
		{
			try
			{
				$registeredPublicKeyCredentialDescriptors[] = $record->getPublicKeyCredentialDescriptor();
			}
			catch (Throwable $e)
			{
				continue;
			}
		}

		Joomla::setSessionVar('userHandle', $repository->getHandleFromUserId($user_id), 'plg_system_passwordless');
		Joomla::setSessionVar('userId', $user_id, 'plg_system_passwordless');

		return $registeredPublicKeyCredentialDescriptors;
	}
}