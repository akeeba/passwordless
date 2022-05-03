<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Joomla\Plugin\System\Passwordless\PluginTraits;

// Protect from unauthorized access
defined('_JEXEC') or die();

use Exception;
use Joomla\CMS\Factory;
use Joomla\CMS\Form\Form;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\Event\Event;
use Joomla\Plugin\System\Passwordless\Extension\Passwordless;
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
	 * User object derived from the displayed user profile data.
	 *
	 * This is required to display the number and names of authenticators already registered when
	 * the user displays the profile view page.
	 *
	 * @var   User|null
	 * @since 1.0.0
	 */
	private static $userFromFormData = null;

	/**
	 * HTMLHelper method to render the WebAuthn user profile field in the profile view page.
	 *
	 * Instead of showing a nonsensical "Website default" label next to the field, this method
	 * displays the number and names of authenticators already registered by the user.
	 *
	 * This static method is set up for use in the onContentPrepareData method of this plugin.
	 *
	 * @param   mixed  $value  Ignored. The WebAuthn profile field is virtual, it doesn't have a
	 *                         stored value. We only use it as a proxy to render a sub-form.
	 *
	 * @return  string
	 * @since   1.0.0
	 */
	public static function renderPasswordlessProfileField($value): string
	{
		if (\is_null(self::$userFromFormData))
		{
			return '';
		}

		/** @var Passwordless $plugin */
		$plugin               = Factory::getApplication()->bootPlugin('passwordless', 'system');
		$credentialRepository = $plugin->getAuthenticationHelper()->getCredentialsRepository();
		$credentials          = $credentialRepository->getAll(self::$userFromFormData->id);
		$authenticators       = array_map(
			function (array $credential) {
				return $credential['label'];
			},
			$credentials
		);

		return Text::plural('PLG_SYSTEM_PASSWORDLESS_FIELD_N_AUTHENTICATORS_REGISTERED', \count($authenticators), implode(', ', $authenticators));
	}

	/**
	 * Adds additional fields to the user editing form
	 *
	 * @throws  Exception
	 */
	public function onContentPrepareForm(Event $event): void
	{
		/**
		 * @var   Form  $form The form to be altered.
		 * @var   mixed $data The associated data for the form.
		 */
		[$form, $data] = $event->getArguments();

		// This feature only applies to HTTPS sites.
		if (!Uri::getInstance()->isSsl())
		{
			return;
		}

		// Check we are manipulating a valid form.
		if (!($form instanceof Form))
		{
			return;
		}

		$name = $form->getName();

		if (!in_array($name, ['com_admin.profile', 'com_users.user', 'com_users.profile', 'com_users.registration']))
		{
			return;
		}

		// Get the user object
		$user = $this->getUserFromData($data);

		// Make sure the loaded user is the correct one
		if (\is_null($user))
		{
			return;
		}

		// Make sure I am either editing myself OR I am a Super User
		if (!$this->canEditUser($user))
		{
			return;
		}

		// Add the fields to the form.
		Log::add('Injecting Akeeba Passwordless Login fields in user profile edit page', Log::INFO, 'plg_system_passwordless');
		Form::addFormPath(JPATH_PLUGINS . '/' . $this->_type . '/' . $this->_name . '/forms');
		$form->loadFile('passwordless', false);
	}

	/**
	 * @param   Event  $event  The event we are handling
	 *
	 * @return  void
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	public function onContentPrepareData(Event $event): void
	{
		/**
		 * @var   string|null       $context The context for the data
		 * @var   array|object|null $data    An object or array containing the data for the form.
		 */
		[$context, $data] = $event->getArguments();

		if (!\in_array($context, ['com_users.profile', 'com_users.user']))
		{
			return;
		}

		self::$userFromFormData = $this->getUserFromData($data);

		if (!HTMLHelper::isRegistered('users.passwordlessPasswordless'))
		{
			HTMLHelper::register('users.passwordlessPasswordless', [__CLASS__, 'renderPasswordlessProfileField']);
		}
	}

	/**
	 * Get the user object based on the ID found in the provided user form data
	 *
	 * @param   array|object|null  $data  The user form data
	 *
	 * @return  User|null  A user object or null if no match is found
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	private function getUserFromData($data): ?User
	{
		$id = null;

		if (\is_array($data))
		{
			$id = $data['id'] ?? null;
		}
		elseif (\is_object($data) && ($data instanceof Registry))
		{
			$id = $data->get('id');
		}
		elseif (\is_object($data))
		{
			$id = $data->id ?? null;
		}

		$user = empty($id)
			? Factory::getApplication()->getIdentity()
			: Factory::getContainer()
			         ->get(UserFactoryInterface::class)
			         ->loadUserById($id);

		// Make sure the loaded user is the correct one
		if ($user->id != $id)
		{
			return null;
		}

		return $user;
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
			return false;
		}

		// Get the currently logged in used
		$myUser = $this->app->getIdentity() ?? new User();

		// I can only edit myself.
		return $myUser->id == $user->id;
	}
}