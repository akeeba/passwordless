<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Joomla\Plugin\System\Passwordless\Extension\Traits;

// Protect from unauthorized access
defined('_JEXEC') or die();

use Exception;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\CMS\User\UserHelper;
use Joomla\Event\Event;
use Joomla\Plugin\System\Passwordless\Credential\Authentication;
use Joomla\Plugin\System\Passwordless\Credential\CredentialsRepository;

/**
 * Ajax handler for akaction=challenge
 *
 * Generates the public key and challenge which is used by the browser when logging in with Webauthn. This is the bit
 * which prevents tampering with the login process and replay attacks.
 *
 * @since 1.0.0
 */
trait AjaxHandlerChallenge
{
	use EventReturnAware;

	/**
	 * Returns the JSON-encoded Public Key Credential Request
	 *
	 * Result: A JSON-encoded object or JSON-encoded false if the username is invalid or no credentials stored
	 *
	 * @throws   Exception
	 * @since    1.0.0
	 */
	public function onAjaxPasswordlessChallenge(Event $event): void
	{
		// Initialize objects
		$input        = $this->app->input;
		$rememberUser = $this->params->get('rememberUser', 1) == 1;

		// Retrieve data from the request
		$username  = $input->getUsername('username', '');
		$returnUrl = base64_encode($this->app->getSession()->get('plg_system_passwordless.returnUrl', Uri::current()));
		$returnUrl = $input->getBase64('returnUrl', $returnUrl);
		$returnUrl = base64_decode($returnUrl);

		/**
		 * For security reasons, if you type in a username we need to remove the user handle cookie.
		 *
		 * For all we know you are trying to log in as a different user. Unsetting the cookie will let us re-evaluate
		 * whether we should store a different cookie when you reload the page.
		 */
		if (!empty($username))
		{
			$this->resetUserHandleCookie();
		}

		// For security reasons the post-login redirection URL must be internal to the site.
		if (!Uri::isInternal($returnUrl))
		{
			// If the URL wasn't internal redirect to the site's root.
			$returnUrl = Uri::base();
		}

		// Get the return URL
		$this->app->getSession()->set('plg_system_passwordless.returnUrl', $returnUrl);

		// Get the user_id from the username, if a username was specified at all
		try
		{
			$user_id = empty($username) ? 0 : UserHelper::getUserId($username);
		}
		catch (Exception $e)
		{
			$user_id = 0;
		}

		// If there was no username set we can look into the user handle cookie for user information
		if (empty($username) && empty($user_id) && $rememberUser)
		{
			[$cookieName,] = $this->getCookieOptions();
			$userHandle = $this->getCookie($cookieName);

			if (!empty($userHandle))
			{
				$repository = new CredentialsRepository();
				$user_id    = $repository->getUserIdFromHandle($userHandle) ?? 0;
			}
		}

		if (!$rememberUser && empty($user_id))
		{
			$this->returnFromEvent($event, json_encode([
				'error' => Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_EMPTY_USERNAME'),
			], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

			return;
		}

		if ($rememberUser && empty($username) && empty($user_id))
		{
			$this->returnFromEvent($event, json_encode([
				'error' => Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_EMPTY_USERNAME_FIRST_TIME'),
			], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

			return;
		}

		if (!empty($username) && empty($user_id))
		{
			$this->returnFromEvent($event, json_encode([
				'error' => Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_INVALID_USERNAME'),
			], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

			return;
		}


		$user = Factory::getContainer()->get(UserFactoryInterface::class)->loadUserById($user_id);
		$publicKeyCredentialRequestOptions = Authentication::getPubkeyRequestOptions($user);

		// Return the JSON encoded data to the caller
		$this->returnFromEvent($event, json_encode($publicKeyCredentialRequestOptions, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
	}
}