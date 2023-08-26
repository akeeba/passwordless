<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Plugin\System\Passwordless\PluginTraits;

defined('_JEXEC') or die();

use Exception;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Layout\FileLayout;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\Event\Event;
use RuntimeException;
use Webauthn\PublicKeyCredentialSource;

/**
 * Ajax handler for akaction=create
 *
 * Handles the browser postback for the credentials creation flow
 *
 * @since  1.0.0
 */
trait AjaxHandlerCreate
{
	/**
	 * Handle the callback to add a new WebAuthn authenticator
	 *
	 * @throws  Exception
	 *
	 * @since   1.0.0
	 */
	public function onAjaxPasswordlessCreate(Event $event): void
	{
		/**
		 * Fundamental sanity check: this callback is only allowed after a Public Key has been created server-side and
		 * the user it was created for matches the current user.
		 *
		 * This is also checked in the validateAuthenticationData() so why check here? In case we have the wrong user
		 * I need to fail early with a Joomla error page instead of falling through the code and possibly displaying
		 * someone else's Webauthn configuration thus mitigating a major privacy and security risk. So, please, DO NOT
		 * remove this sanity check!
		 */
		$session      = $this->getApplication()->getSession();
		$storedUserId = $session->get('plg_system_passwordless.registration_user_id', 0);
		$thatUser     = empty($storedUserId)
			? $this->getApplication()->getIdentity()
			: Factory::getContainer()->get(UserFactoryInterface::class)->loadUserById($storedUserId);
		$myUser       = $this->getApplication()->getIdentity() ?? new User();

		if ($thatUser->guest || ($thatUser->id != $myUser->id))
		{
			// Unset the session variables used for registering authenticators (security precaution).
			$session->remove('plg_system_passwordless.registration_user_id');
			$session->remove('plg_system_passwordless.publicKeyCredentialCreationOptions');

			// Politely tell the presumed hacker trying to abuse this callback to go away.
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_USER'));
		}

		// Get the credentials repository object. It's outside the try-catch because I also need it to display the GUI.
		$credentialRepository = $this->authenticationHelper->getCredentialsRepository();

		// Try to validate the browser data. If there's an error I won't save anything and pass the message to the GUI.
		try
		{
			$input = $this->getApplication()->input;

			// Retrieve the data sent by the device
			$data = $input->get('data', '', 'raw');

			$publicKeyCredentialSource = $this->authenticationHelper->validateAttestationResponse($data);

			if (!is_object($publicKeyCredentialSource) || !($publicKeyCredentialSource instanceof PublicKeyCredentialSource))
			{
				throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_NO_ATTESTED_DATA'));
			}

			$credentialRepository->saveCredentialSource($publicKeyCredentialSource);
		}
		catch (Exception $e)
		{
			$error                     = $e->getMessage();
			$publicKeyCredentialSource = null;
		}

		// Unset the session variables used for registering authenticators (security precaution).
		$session->remove('plg_system_passwordless.registration_user_id');
		$session->remove('plg_system_passwordless.publicKeyCredentialCreationOptions');

		// Render the GUI and return it
		$layoutParameters = [
			'user'        => $thatUser,
			'allow_add'   => $thatUser->id == $myUser->id,
			'credentials' => $credentialRepository->getAll($thatUser->id),
			'showImages'  => $this->params->get('showImages', 1) == 1,
			'application' => $this->getApplication(),
		];

		if (isset($error) && !empty($error))
		{
			$layoutParameters['error'] = $error;
		}

		$layout = new FileLayout('akeeba.passwordless.manage', JPATH_SITE . '/plugins/system/passwordless/layout');

		$this->returnFromEvent($event, $layout->render($layoutParameters));
	}
}