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
use Joomla\CMS\User\User;
use Joomla\Plugin\System\Passwordless\Credential\CredentialsRepository;

/**
 * Ajax handler for akaction=savelabel
 *
 * Deletes a security key
 *
 * @since 1.0.0
 */
trait AjaxHandlerDelete
{
	/**
	 * Handle the callback to remove an authenticator
	 *
	 * @return  bool
	 * @throws  Exception
	 *
	 * @since   1.0.0
	 */
	public function onAjaxPasswordlessDelete(): bool
	{
		// Initialize objects
		$input      = $this->app->input;
		$repository = new CredentialsRepository();

		// Retrieve data from the request
		$credential_id = $input->getBase64('credential_id', '');

		// Is this a valid credential?
		if (empty($credential_id))
		{
			return false;
		}

		$credential_id = base64_decode($credential_id);

		if (empty($credential_id) || !$repository->has($credential_id))
		{
			return false;
		}

		// Make sure I am editing my own key
		try
		{
			$user              = $this->app->getIdentity() ?? new User();
			$credential_handle = $repository->getUserHandleFor($credential_id);
			$my_handle         = $repository->getHandleFromUserId($user->id);
		}
		catch (Exception $e)
		{
			return false;
		}

		if ($credential_handle !== $my_handle)
		{
			return false;
		}

		// Delete the record
		try
		{
			$repository->remove($credential_id);
		}
		catch (Exception $e)
		{
			return false;
		}

		/**
		 * Remove the user handle cookie and session variable
		 *
		 * Deleting a WebAuthn credential might have changed whether the currently logged in user has any WebAuthn
		 * credentials. Deleting the cookie and the session variable we allow the next page load to reaffirm the
		 * existence of WebAuthn credentials and set the userHandle cookie and session variable if necessary.
		 * If no credentials are left, no worries! We have already removed the obsolete cookie and session variable.
		 */
		$this->resetUserHandleCookie();

		return true;
	}
}