<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2021 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Passwordless\PluginTraits;

// Protect from unauthorized access
defined('_JEXEC') or die();

use Exception;
use Joomla\CMS\Factory;

trait CookieHandling
{
	/**
	 * Sets a cookie
	 *
	 * @param   string  $cookieName   Name of the cookie
	 * @param   string  $cookieValue  Value to store in the cookie
	 * @param   int     $expireDays   Expiration, in days from now
	 *
	 * @return  void
	 */
	public function setCookie(string $cookieName, string $cookieValue, int $expireDays = 30): void
	{
		try
		{
			$app = Factory::getApplication();
		}
		catch (Exception $e)
		{
			return;
		}

		$path            = $app->get('cookie_path', '/');
		$domain          = $app->get('cookie_domain', filter_input(INPUT_SERVER, 'HTTP_HOST'));
		$secure          = $app->get('force_ssl', 0) == 2;
		$httpOnly        = true;
		$expireTimestamp = time() + (86400 * $expireDays);

		$app->input->cookie->set($cookieName, $cookieValue, $expireTimestamp, $path, $domain, $secure, $httpOnly);
	}

	/**
	 * Get the value of a stored cookie
	 *
	 * @param   string       $cookieName    Name of the cookie
	 * @param   string|null  $defaultValue  Default value to return if it's not set
	 *
	 * @return string|null  The stored cookie value (or the default, if it's not set)
	 */
	public function getCookie(string $cookieName, ?string $defaultValue = null): ?string
	{
		try
		{
			$app = Factory::getApplication();
		}
		catch (Exception $e)
		{
			return $defaultValue;
		}

		return $app->input->cookie->get($cookieName, $defaultValue, 'raw');
	}

}