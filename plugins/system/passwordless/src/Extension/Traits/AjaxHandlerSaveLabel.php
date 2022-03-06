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
 * Stores a new label for a security key
 *
 * @since  1.0.0
 */
trait AjaxHandlerSaveLabel
{
	/**
	 * Handle the callback to rename an authenticator
	 *
	 * @return  bool
	 *
	 * @throws  Exception
	 *
	 * @since   1.0.0
	 */
	public function onAjaxPasswordlessSavelabel(): bool
	{
		// Initialize objects
		$input      = $this->app->input;
		$repository = new CredentialsRepository();

		// Retrieve data from the request
		$credential_id = $input->getBase64('credential_id', '');
		$new_label     = $input->getString('new_label', '');

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
			$credential_handle = $repository->getUserHandleFor($credential_id);
			$user              = $this->app->getIdentity() ?? new User();
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

		// Make sure the new label is not empty
		if (empty($new_label))
		{
			return false;
		}

		// Save the new label
		try
		{
			$repository->setLabel($credential_id, $new_label);
		}
		catch (Exception $e)
		{
			return false;
		}

		return true;
	}
}