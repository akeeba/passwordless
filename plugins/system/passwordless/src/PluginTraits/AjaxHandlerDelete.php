<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Plugin\System\Passwordless\PluginTraits;

defined('_JEXEC') or die();

use Exception;
use Joomla\CMS\User\User;
use Joomla\Event\Event;

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
	 * @throws  Exception
	 *
	 * @since   1.0.0
	 */
	public function onAjaxPasswordlessDelete(Event $event): void
	{
		// Initialize objects
		$input      = $this->getApplication()->input;
		$repository = $this->authenticationHelper->getCredentialsRepository();

		// Retrieve data from the request
		$credentialId = $input->getBase64('credential_id', '');

		// Is this a valid credential?
		if (empty($credentialId))
		{
			$this->returnFromEvent($event, false);

			return;
		}

		$credentialId = base64_decode($credentialId);

		if (empty($credentialId) || !$repository->has($credentialId))
		{
			$this->returnFromEvent($event, false);

			return;
		}

		// Make sure I am editing my own key
		try
		{
			$user             = $this->getApplication()->getIdentity() ?? new User();
			$credentialHandle = $repository->getUserHandleFor($credentialId);
			$myHandle         = $repository->getHandleFromUserId($user->id);
		}
		catch (Exception $e)
		{
			$this->returnFromEvent($event, false);

			return;
		}

		if ($credentialHandle !== $myHandle)
		{
			$this->returnFromEvent($event, false);

			return;
		}

		// Delete the record
		try
		{
			$repository->remove($credentialId);
		}
		catch (Exception $e)
		{
			$this->returnFromEvent($event, false);

			return;
		}

		$this->returnFromEvent($event, true);
	}
}