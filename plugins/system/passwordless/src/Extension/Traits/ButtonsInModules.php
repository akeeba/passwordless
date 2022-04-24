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
use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\UserHelper;
use Joomla\Event\Event;
use Joomla\Plugin\System\Passwordless\Helper\Integration;

/**
 * Inserts Webauthn buttons into login modules
 */
trait ButtonsInModules
{
	use EventReturnAware;

	/**
	 * Creates additional login buttons
	 *
	 * @return  void
	 *
	 * @throws  Exception
	 *
	 * @see     AuthenticationHelper::getLoginButtons()
	 *
	 * @since   1.0.0
	 */
	public function onUserLoginButtons(Event $event): void
	{
		/** @var string $form The HTML ID of the form we are enclosed in */
		[$form] = $event->getArguments();

		// Append the social login buttons content
		Log::add(Log::INFO, 'plg_system_passwordless', 'Injecting buttons using the Joomla 4 way.');

		$this->addLoginCSSAndJavascript();

		$randomId = 'akpwl-login-' . UserHelper::genRandomPassword(12) . '-' . UserHelper::genRandomPassword(8);

		// Get local path to image
		$image = HTMLHelper::_('image', 'plg_system_passwordless/webauthn.svg', '', '', true, true);

		// If you can't find the image then skip it
		$image = $image ? JPATH_ROOT . substr($image, \strlen(Uri::root(true))) : '';

		// Extract image if it exists
		$image = file_exists($image) ? file_get_contents($image) : '';

		$this->returnFromEvent($event, [
			[
				'label'                  => 'PLG_SYSTEM_PASSWORDLESS_LOGIN_LABEL',
				'tooltip'                => 'PLG_SYSTEM_PASSWORDLESS_LOGIN_DESC',
				'id'                     => $randomId,
				'data-passwordless-form' => $form,
				'svg'                    => $image,
				'class'                  => 'plg_system_passwordless_login_button',
			],
		]);
	}

	/**
	 * Injects the Webauthn CSS and Javascript for frontend logins, but only once per page load.
	 *
	 * @return  void
	 */
	private function addLoginCSSAndJavascript(): void
	{
		static $loaded = false;

		if (!($this->app instanceof CMSApplication))
		{
			return;
		}

		$wam = $this->app->getDocument()->getWebAssetManager();
		$wam->getRegistry()->addExtensionRegistryFile('plg_system_passwordless');
		$wam->useScript('plg_system_passwordless.login');

		if ($loaded)
		{
			return;
		}

		// Load language strings client-side
		Text::script('PLG_SYSTEM_PASSWORDLESS_ERR_CANNOT_FIND_USERNAME');
		Text::script('PLG_SYSTEM_PASSWORDLESS_ERR_INVALID_USERNAME');

		// Store the current URL as the default return URL after login (or failure)
		$this->app->getSession()->set('plg_system_passwordless.returnUrl', Uri::current());

		$loaded = true;
	}

}