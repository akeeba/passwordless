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
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\UserHelper;
use Joomla\Plugin\System\Passwordless\Helper\Integration;

/**
 * Inserts Webauthn buttons into login modules
 */
trait ButtonsInModules
{
	/**
	 * Creates additional login buttons
	 *
	 * @param   string  $form  The HTML ID of the form we are enclosed in
	 *
	 * @return  array
	 *
	 * @throws  Exception
	 *
	 * @see     AuthenticationHelper::getLoginButtons()
	 *
	 * @since   1.0.0
	 */
	public function onUserLoginButtons(string $form): array
	{
		// Append the social login buttons content
        Log::add(Log::INFO, 'plg_system_passwordless', 'Injecting buttons using the Joomla 4 way.');

		Integration::addLoginCSSAndJavascript();

		$randomId = 'akpwl-login-' . UserHelper::genRandomPassword(12) . '-' . UserHelper::genRandomPassword(8);
		$uri      = new Uri(Uri::base() . 'index.php');

		$uri->setVar($this->app->getFormToken(), '1');

		// Get local path to image
		$image = HTMLHelper::_('image', 'plg_system_passwordless/webauthn.svg', '', '', true, true);

		// If you can't find the image then skip it
		$image = $image ? JPATH_ROOT . substr($image, \strlen(Uri::root(true))) : '';

		// Extract image if it exists
		$image = file_exists($image) ? file_get_contents($image) : '';

		return [
			[
				'label'                 => 'PLG_SYSTEM_PASSWORDLESS_LOGIN_LABEL',
				'tooltip'               => 'PLG_SYSTEM_PASSWORDLESS_LOGIN_DESC',
				'id'                    => $randomId,
				'data-passwordless-url' => $uri->toString(),
				'data-webauthn-form'    => $form,
				//'image'                 => 'plg_system_passwordless/webauthn-black.png',
				'class'                 => 'plg_system_passwordless_login_button',
				'svg'                   => $image,
			],
		];
	}
}