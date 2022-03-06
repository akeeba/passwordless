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
use Joomla\Event\Event;
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
	use EventReturnAware;

	/**
	 * Handle the callback to rename an authenticator
	 *
	 * @throws  Exception
	 *
	 * @since   1.0.0
	 */
	public function onAjaxPasswordlessSavelabel(Event $event): void
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
			$this->returnFromEvent($event, false);

			return;
		}

		$credential_id = base64_decode($credential_id);

		if (empty($credential_id) || !$repository->has($credential_id))
		{
			$this->returnFromEvent($event, false);

			return;
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
			$this->returnFromEvent($event, false);

			return;
		}

		if ($credential_handle !== $my_handle)
		{
			$this->returnFromEvent($event, false);

			return;
		}

		// Make sure the new label is not empty
		if (empty($new_label))
		{
			$this->returnFromEvent($event, false);

			return;
		}

		// Save the new label
		try
		{
			$repository->setLabel($credential_id, $new_label);
		}
		catch (Exception $e)
		{
			$this->returnFromEvent($event, false);

			return;
		}

		$this->returnFromEvent($event, true);
	}
}