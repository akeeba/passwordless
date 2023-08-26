<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Plugin\System\Passwordless\PluginTraits;

defined('_JEXEC') or die();

use Akeeba\Plugin\System\Passwordless\Extension\Passwordless;
use Exception;
use Joomla\CMS\Factory;
use Joomla\CMS\Form\Form;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\Database\DatabaseDriver;
use Joomla\Database\ParameterType;
use Joomla\Event\Event;
use Joomla\Registry\Registry;
use Joomla\Utilities\ArrayHelper;

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
		[$form, $data] = array_values($event->getArguments());

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
		[$context, $data] = array_values($event->getArguments());

		if (!\in_array($context, ['com_users.profile', 'com_users.user']))
		{
			return;
		}

		self::$userFromFormData = $this->getUserFromData($data);

		if (!HTMLHelper::isRegistered('users.passwordlessPasswordless'))
		{
			HTMLHelper::register('users.passwordlessPasswordless', [__CLASS__, 'renderPasswordlessProfileField']);
		}

		/**
		 * The $data must be an object and have an id property but not a profile property (that'd be the profile already
		 * loaded by Joomla).
		 */
		if (!is_object($data) || !isset($data->id) || isset($data->passwordless))
		{
			return;
		}

		// Get the user ID
		$userId = (int) ($data->id ?? 0);

		// Make sure we have a positive integer user ID
		if ($userId <= 0)
		{
			return;
		}

		// Load the profile data from the database.
		try
		{
			/** @var DatabaseDriver $db */
			$db         = $this->getDatabase();
			$profileKey = 'passwordless.%';
			$query      = $db->getQuery(true)
			                 ->select([
				                 $db->quoteName('profile_key'),
				                 $db->quoteName('profile_value'),
			                 ])
			                 ->from($db->quoteName('#__user_profiles'))
			                 ->where($db->quoteName('user_id') . ' = :user_id')
			                 ->where($db->quoteName('profile_key') . ' LIKE :profile_key')
			                 ->order($db->quoteName('ordering'))
			                 ->bind(':user_id', $userId, ParameterType::INTEGER)
			                 ->bind(':profile_key', $profileKey);

			$results = $db->setQuery($query)->loadAssocList('profile_key', 'profile_value');

			$data->passwordless = [];

			foreach ($results as $k => $v)
			{
				$k = str_replace('passwordless.', '', $k);

				$data->passwordless[$k] = $v;
			}
		}
		catch (Exception $e)
		{
			// We suppress any database error. It means we have no data set.
		}
	}

	public function onUserAfterSave(Event $event)
	{
		[$data, $isNew, $result, $error] = array_values($event->getArguments());

		$userId = ArrayHelper::getValue($data, 'id', 0, 'int');

		if (!$userId || !$result || !isset($data['passwordless']) || !count($data['passwordless']))
		{
			return;
		}

		/** @var DatabaseDriver $db */
		$db         = $this->getDatabase();
		$profileKey = 'passwordless.%';
		$query      = $db->getQuery(true)
		                 ->delete($db->quoteName('#__user_profiles'))
		                 ->where($db->quoteName('user_id') . ' = :user_id')
		                 ->where($db->quoteName('profile_key') . ' LIKE :profile_key')
		                 ->bind(':user_id', $userId, ParameterType::INTEGER)
		                 ->bind(':profile_key', $profileKey);

		try
		{
			$db->setQuery($query)->execute();
		}
		catch (Exception $e)
		{
			return;
		}

		if (empty($data['passwordless']))
		{
			return;
		}

		$order = 1;

		$query = $db->getQuery(true)
		            ->insert($db->quoteName('#__user_profiles'))
		            ->columns([
			            $db->quoteName('user_id'),
			            $db->quoteName('profile_key'),
			            $db->quoteName('profile_value'),
			            $db->quoteName('ordering'),
		            ]);

		foreach ($data['passwordless'] as $k => $v)
		{
			if ($k == 'passwordless')
			{
				continue;
			}

			$query->values(implode(',', $query->bindArray([
				$userId,
				'passwordless.' . $k,
				$v,
				$order++,
			], [
				ParameterType::INTEGER,
				ParameterType::STRING,
				ParameterType::STRING,
				ParameterType::INTEGER,
			])));
		}

		try
		{
			$db->setQuery($query)->execute();
		}
		catch (Exception $e)
		{
			echo $query;
			echo $e->getMessage();
			die('poutsa kavlomeni');
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
		$myUser = $this->getApplication()->getIdentity() ?? new User();

		// I can only edit myself.
		return $myUser->id == $user->id;
	}
}