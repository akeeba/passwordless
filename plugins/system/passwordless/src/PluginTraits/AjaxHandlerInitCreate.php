<?php
/**
 * @package     Joomla.Plugin
 * @subpackage  System.Webauthn
 *
 * @copyright   (C) 2022 Open Source Matters, Inc. <https://www.joomla.org>
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

namespace Akeeba\Plugin\System\Passwordless\PluginTraits;

// Protect from unauthorized access
\defined('_JEXEC') or die();

use Joomla\CMS\Factory;
use Joomla\CMS\User\User;
use Joomla\Event\Event;

/**
 * Ajax handler for akaction=initcreate
 *
 * Returns the Public Key Creation Options to start the attestation ceremony on the browser.
 *
 * @since  2.0.0
 */
trait AjaxHandlerInitCreate
{
	/**
	 * Returns the Public Key Creation Options to start the attestation ceremony on the browser.
	 *
	 * @param   Event  $event  The event we are handling
	 *
	 * @return  void
	 * @since   2.0.0
	 */
	public function onAjaxPasswordlessInitcreate(Event $event): void
	{
		// Make sure I have a valid user
		$user = $this->getApplication()->getIdentity();

		if (!($user instanceof User) || $user->guest)
		{
			$this->returnFromEvent($event, []);

			return;
		}

		// I need the server to have either GMP or BCComp support to attest new authenticators
		if (function_exists('gmp_intval') === false && function_exists('bccomp') === false)
		{
			$this->returnFromEvent($event, []);

			return;
		}

		$session = $this->getApplication()->getSession();
		$session->set('plg_system_passwordless.registration_user_id', $user->id);

		$resident = $this->getApplication()->input->getBool('resident', false);

		$this->returnFromEvent($event, $this->authenticationHelper->getPubKeyCreationOptions($user, $resident));
	}
}
