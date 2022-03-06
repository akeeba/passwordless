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

/**
 * Handles the cookies for this plugin.
 *
 * @since  1.0.0
 */
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
	 * @since   1.0.0
	 */
	private function setCookie(string $cookieName, string $cookieValue, int $expireDays = 30): void
	{
		$path            = $this->app->get('cookie_path', '/');
		$domain          = $this->app->get('cookie_domain', filter_input(INPUT_SERVER, 'HTTP_HOST'));
		$secure          = $this->app->get('force_ssl', 0) == 2;
		$httpOnly        = true;
		$expireTimestamp = time() + (86400 * $expireDays);

		$this->app->input->cookie->set($cookieName, $cookieValue, $expireTimestamp, $path, $domain, $secure, $httpOnly);
	}

	/**
	 * Get the value of a stored cookie
	 *
	 * @param   string       $cookieName    Name of the cookie
	 * @param   string|null  $defaultValue  Default value to return if it's not set
	 *
	 * @return  string|null  The stored cookie value (or the default, if it's not set)
	 * @since   1.0.0
	 */
	private function getCookie(string $cookieName, ?string $defaultValue = null): ?string
	{
		try
		{
			return $this->app->input->cookie->get($cookieName, $defaultValue, 'raw');
		}
		catch (Exception $e)
		{
			return $defaultValue;
		}
	}

}