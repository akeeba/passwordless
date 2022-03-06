<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Joomla\Plugin\System\Passwordless\Helper;

// Protect from unauthorized access
defined('_JEXEC') or die();

use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Uri\Uri;

abstract class Integration
{
	/**
	 * Injects the Webauthn CSS and Javascript for frontend logins, but only once per page load.
	 *
	 * @return  void
	 */
	public static function addLoginCSSAndJavascript(): void
	{
		static $loaded = false;

		/** @var CMSApplication $app */
		$app = Factory::getApplication();

		if (!($app instanceof CMSApplication))
		{
			return;
		}

		$app->getDocument()->getWebAssetManager()
			->usePreset('plg_system_passwordless.login');

		if ($loaded)
		{
			return;
		}

		// Load language strings client-side
		Text::script('PLG_SYSTEM_PASSWORDLESS_ERR_CANNOT_FIND_USERNAME');
		Text::script('PLG_SYSTEM_PASSWORDLESS_ERR_INVALID_USERNAME');

		// Store the current URL as the default return URL after login (or failure)
		$app->getSession()->set('plg_system_passwordless.returnUrl', Uri::current());

		$loaded = true;
	}
}