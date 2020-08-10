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
use Joomla\CMS\User\User;
use Throwable;
use Webauthn\PublicKeyCredentialUserEntity;

trait UserHandleCookie
{
	use CookieHandling;

	/**
	 * Makes sure we have a cookie with the user handle which will be used for the WebAuthn login flow.
	 *
	 * @return  void
	 */
	public function onAfterInitialiseCookie()
	{
		// Should I even remember the user handle?
		$rememberUser = $this->params->get('rememberUser', 1) == 1;

		if (!$rememberUser)
		{
			$this->resetUserHandleCookie();

			return;
		}

		// Am I logged in?
		$user = Joomla::getUser();

		if ($user->guest)
		{
			return;
		}

		// Do I have WebAuthn credentials?
		$hasWebAuthn = $this->hasWebAuthnCredentials($user);

		if (!$hasWebAuthn)
		{
			return;
		}

		// Do I have a cookie?
		[$cookieName, $expireDays] = $this->getCookieOptions();
		$userHandle = $this->getCookie($cookieName);

		if (!is_null($userHandle))
		{
			return;
		}

		// Set cookie
		try
		{
			$repository = new CredentialRepository();
			$userHandle = $repository->getHandleFromUserId($user->id);
		}
		catch (Exception $e)
		{
			return;
		}

		$this->setCookie($cookieName, $userHandle, $expireDays);
	}

	/**
	 * Reset the user handle cookie and session variable.
	 *
	 * This is necessary every time we add or remove WebAuthn credentials because this action may have changed whether
	 * the user has *any* WebAuthn credentials.
	 *
	 * When we remove the last credential we need to unset the cookie and session variable. Since this is called from
	 * onAjaxPasswordlessDelete we fulfil that requirement. The next time the plugin runs it will see that there are
	 * no WebAuthn credentials and will NOT set the cookie.
	 *
	 * When we add the first credential we need to set the cookie next time around. Since this is called from
	 * onAjaxPasswordlessCreate we fulfil this requirement. The next time the plugin runs it will see that there is at
	 * least one WebAuthn credential and WILL set the cookie.
	 */
	protected function resetUserHandleCookie(): void
	{
		[$cookieName, ] = $this->getCookieOptions();

		try
		{
			// This sets the session variable to null, effectively "unsetting" it.
			Joomla::unsetSessionVar('hasWebauthnCredentials', 'plg_system_passwordless');

			// The best way to remove a cookie is to set its expiration time to a year ago from now.
			$this->setCookie($cookieName, '', -365);
		}
		catch (Throwable $e)
		{
			return;
		}
	}

	/**
	 * Get the user handle cookie options
	 *
	 * @return  array
	 */
	protected function getCookieOptions(): array
	{
		return [
			$this->params->get('userHandleCookieName', 'akWebAuthnHandle'),
			$this->params->get('userHandleCookieExpiration', 30),
		];
	}

	/**
	 * Does the currently logged in user have WebAuthn credentials?
	 *
	 * @param   User  $user
	 *
	 * @return  bool
	 */
	private function hasWebAuthnCredentials(User $user): bool
	{
		$hasCredentials = Joomla::getSessionVar('hasWebauthnCredentials', null, 'plg_system_passwordless');

		if (!is_null($hasCredentials))
		{
			return (bool) $hasCredentials;
		}

		try
		{
			$repository  = new CredentialRepository();
			$userHandle  = $repository->getHandleFromUserId($user->id);
			$userEntity  = new PublicKeyCredentialUserEntity('', $userHandle, '');
			$credentials = $repository->findAllForUserEntity($userEntity);

			$hasCredentials = count($credentials) > 0;
		}
		catch (Exception $e)
		{
			$hasCredentials = false;
		}

		Joomla::setSessionVar('hasWebauthnCredentials', $hasCredentials, 'plg_system_passwordless');

		return $hasCredentials;
	}
}