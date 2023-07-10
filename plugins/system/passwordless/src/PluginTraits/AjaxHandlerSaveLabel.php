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
 * Stores a new label for a security key
 *
 * @since  1.0.0
 */
trait AjaxHandlerSaveLabel
{
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
		$input      = $this->getApplication()->input;
		$repository = $this->authenticationHelper->getCredentialsRepository();

		// Retrieve data from the request
		$credentialId = $input->getBase64('credential_id', '');
		$newLabel     = $input->getString('new_label', '');

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
			$credentialHandle = $repository->getUserHandleFor($credentialId);
			$user             = $this->getApplication()->getIdentity() ?? new User();
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

		// Make sure the new label is not empty
		if (empty($newLabel))
		{
			$this->returnFromEvent($event, false);

			return;
		}

		// Save the new label
		try
		{
			$repository->setLabel($credentialId, $newLabel);
		}
		catch (Exception $e)
		{
			$this->returnFromEvent($event, false);

			return;
		}

		$this->returnFromEvent($event, true);
	}
}