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
use Joomla\CMS\Factory;
use Joomla\CMS\Form\Form;
use Joomla\CMS\Log\Log;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\Registry\Registry;

/**
 * Add extra fields in the User Profile page.
 *
 * This class only injects the custom form fields. The actual interface is rendered through JFormFieldWebauthn.
 *
 * @see JFormFieldWebauthn::getInput()
 */
trait UserProfileFields
{
	/**
	 * Adds additional fields to the user editing form
	 *
	 * @param   Form   $form  The form to be altered.
	 * @param   mixed  $data  The associated data for the form.
	 *
	 * @return  boolean
	 *
	 * @throws  Exception
	 */
	public function onContentPrepareForm(Form $form, $data)
	{
		// Check we are manipulating a valid form.
		if (!($form instanceof Form))
		{
			return true;
		}

		$name = $form->getName();

		if (!in_array($name, ['com_admin.profile', 'com_users.user', 'com_users.profile', 'com_users.registration']))
		{
			return true;
		}

		// Get the user ID
		$id = null;

		if (is_array($data))
		{
			$id = isset($data['id']) ? $data['id'] : null;
		}
		elseif (is_object($data) && is_null($data) && ($data instanceof Registry))
		{
			$id = $data->get('id');
		}
		elseif (is_object($data) && !is_null($data))
		{
			$id = isset($data->id) ? $data->id : null;
		}

		$user = Factory::getContainer()->get(UserFactoryInterface::class)->loadUserById($id);

		// Make sure the loaded user is the correct one
		if ($user->id != $id)
		{
			return true;
		}

		// Make sure I am either editing myself OR I am a Super User
		if (!$this->canEditUser($user))
		{
			return true;
		}

		// Add the fields to the form.
		Log::add(Log::INFO, 'plg_system_passwordless', 'Injecting Akeeba Passwordless Login fields in user profile edit page');
		Form::addFormPath(dirname(__FILE__) . '/../../fields');
		$form->loadFile('passwordless', false);

		return true;
	}

	/**
	 * Is the current user allowed to edit the social login configuration of $user? To do so I must either be editing my
	 * own account OR I have to be a Super User.
	 *
	 * @param   ?User  $user  The user you want to know if we're allowed to edit
	 *
	 * @return  bool
	 *
	 * @since   1.0.0
	 */
	private function canEditUser(?User $user = null): bool
	{
		// I can edit myself, but Guests can't have passwordless logins associated
		if (empty($user) || $user->guest)
		{
			return true;
		}

		// Get the currently logged in used
		$myUser = $this->app->getIdentity() ?? new User();

		// I can edit myself. If I'm a Super user I can edit other users too.
		return ($myUser->id == $user->id) || $myUser->authorise('core.admin');
	}

}