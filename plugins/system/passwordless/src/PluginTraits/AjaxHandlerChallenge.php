<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Joomla\Plugin\System\Passwordless\PluginTraits;

// Protect from unauthorized access
defined('_JEXEC') or die();

use Exception;
use Joomla\CMS\Factory;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\CMS\User\UserHelper;
use Joomla\Event\Event;

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
		$session      = $this->app->getSession();
		$input        = $this->app->input;

		// Get plugin configuration
		$allowResident = $this->params->get('allowResident', 1) == 1;

		// Retrieve data from the request
		$username  = $input->getUsername('username', '');
		$returnUrl = base64_encode($session->get('plg_system_passwordless.returnUrl', Uri::current()));
		$returnUrl = $input->getBase64('returnUrl', $returnUrl);
		$returnUrl = base64_decode($returnUrl);

		// For security reasons the post-login redirection URL must be internal to the site.
		if (!Uri::isInternal($returnUrl))
		{
			// If the URL wasn't internal redirect to the site's root.
			$returnUrl = Uri::base();
		}

		// Get the return URL
		$session->set('plg_system_passwordless.returnUrl', $returnUrl);

		// Do I have a username?
		if (!$allowResident && empty($username))
		{
			$this->returnFromEvent($event, false);

			return;
		}

		// Is the username valid?
		try
		{
			$userId = ($allowResident && empty($username)) ? 0 : UserHelper::getUserId($username);
		}
		catch (Exception $e)
		{
			$userId = 0;
		}

		if ($userId <= 0 && !$allowResident)
		{
			$this->returnFromEvent($event, false);

			return;
		}

		try
		{
			$myUser = Factory::getContainer()->get(UserFactoryInterface::class)->loadUserById($userId);
		}
		catch (Exception $e)
		{
			$myUser = new User;
		}

		if (!$allowResident && ($myUser->id != $userId || $myUser->guest))
		{
			$this->returnFromEvent($event, false);

			return;
		}

		$effectiveUser = ($allowResident && $userId === 0) ? null : $myUser;
		$publicKeyCredentialRequestOptions = $this->authenticationHelper->getPubkeyRequestOptions($effectiveUser);

		$session->set('plg_system_passwordless.userId', $userId);

		// Return the JSON encoded data to the caller
		$this->returnFromEvent($event, json_encode($publicKeyCredentialRequestOptions, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
	}
}