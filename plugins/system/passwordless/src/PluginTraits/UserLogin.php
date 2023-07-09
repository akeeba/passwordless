<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Plugin\System\Passwordless\PluginTraits;

defined('_JEXEC') || die;

use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Component\ComponentHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserHelper;
use Joomla\Database\ParameterType;
use Joomla\Event\Event;

trait UserLogin
{
	/**
	 * Handle a successful login.
	 *
	 * If the logged in user has one or more passwordless methods and they just logged in with a username and password
	 * we will decline the login and print a custom message. This is the same set of messages printed when they use the
	 * wrong password, making it impossible for attackers to know if they have guessed the correct username.
	 *
	 * @param   Event  $event  The event we are handling
	 *
	 * @since   2.0.0
	 */
	public function onUserLogin(Event $event)
	{
		// Get the login event arguments
		[$userData, $options] = $event->getArguments();
		$userData = $userData ?: [];

		// Only trigger when we are logging in with a username and password (auth type 'Joomla').
		if (($userData['type'] ?? '') !== 'Joomla')
		{
			return;
		}

		// Get the effective user
		$user = $this->getLoginUserObject($userData);

		// Has the user disabled password authentication on their user account?
		if (!$this->isApplicableUser($user))
		{
			return;
		}

		// Logout the user and close the session.
		$logoutOptions = [];

		$this->app->logout($user->id, $logoutOptions);
		$this->app->getSession()->close();

		// Get a valid return URL.
		$return = $this->app->input->getBase64('return', '');
		$return = !empty($return) ? @base64_decode($return) : '';
		$return = $return ?: Uri::base();

		// For security reasons we cannot allow a return IRL that's outside the current site.
		if (!Uri::isInternal($return))
		{
			// If the URL wasn't internal redirect to the site's root.
			$return = Uri::base();
		}

		// Redirect the user and display a message notifying them they have to log in with Passwordless.
		$this->app->enqueueMessage(
			Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_NOPASSWORDLOGIN'),
			CMSApplication::MSG_WARNING
		);
		// -- This is intentional; it will confuse attackers by making impossible to tell if the password was wrong.
		$this->app->enqueueMessage(
			Text::_('JGLOBAL_AUTH_INVALID_PASS'),
			CMSApplication::MSG_WARNING
		);
		$this->app->redirect($return);
	}

	/**
	 * Handle a login failure.
	 *
	 * This is used to display our custom message for all users who have disabled password logins when they have at
	 * least one Passwordless method enabled. This means that both successful and failed logins for these users will
	 * display the same set of messages, making it virtually impossible for an attacker to discern if they guessed the
	 * right password or not. Yes, it also tells the attacker that the specific username exists, has passwordless
	 * authentication enabled and the user chose not to login with a username and password. So what? Usernames should be
	 * treated as PUBLIC information.
	 *
	 * @param   Event  $event  The event we are handling
	 *
	 * @return  void
	 *
	 * @since   2.0.0
	 */
	public function onUserLoginFailure(Event $event)
	{
		[$response] = $event->getArguments();

		// Only trigger when we are logging in with a username and password (auth type 'Joomla').
		if (($response['type'] ?? '') !== 'Joomla')
		{
			return;
		}

		// Get the effective user
		$user = $this->getLoginUserObject($response);

		// Has the user disabled password authentication on their user account?
		if (!$this->isApplicableUser($user))
		{
			return;
		}

		// Let's muddy the waters
		$this->app->enqueueMessage(
			Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_NOPASSWORDLOGIN'),
			CMSApplication::MSG_WARNING
		);
	}

	private function isApplicableUser(?User $user): bool
	{
		if (empty($user) || $user->guest || empty($user->id) || $user->id <= 0)
		{
			return false;
		}

		// Does this user have passwordless methods?
		$entity      = $this->authenticationHelper->getUserEntity($user);
		$credentials = $this->authenticationHelper->getCredentialsRepository()->findAllForUserEntity($entity);

		if (count($credentials) < 1)
		{
			return false;
		}

		// Does this user prefer to only use passwordless login?
		$db         = $this->db;
		$userId     = $user->id;
		$profileKey = 'passwordless.noPassword';
		$query      = $db->getQuery(true)
		                 ->select($db->quoteName('profile_value'))
		                 ->from($db->quoteName('#__user_profiles'))
		                 ->where($db->quoteName('user_id') . ' = :user_id')
		                 ->where($db->quoteName('profile_key') . ' = :profile_key')
		                 ->bind(':user_id', $userId, ParameterType::INTEGER)
		                 ->bind(':profile_key', $profileKey);

		try
		{
			$preference = $db->setQuery($query)->loadResult() ?: 0;
		}
		catch (\Exception $e)
		{
			$preference = 0;
		}

		if ($preference == 0)
		{
			return false;
		}

		if ($preference == 1)
		{
			return true;
		}

		return count($credentials) > 1;
	}

	/**
	 * Get a Joomla user object based on the login success or login failure information
	 *
	 * @param   array  $loginInformation  The user data from a login success or failure event.
	 *
	 * @return  User  The Joomla User object
	 *
	 * @since   2.0.0
	 */
	private function getLoginUserObject(array $loginInformation): User
	{
		$instance = new User();

		if ($id = intval(UserHelper::getUserId($loginInformation['username'])))
		{
			$instance->load($id);

			return $instance;
		}

		$config           = ComponentHelper::getParams('com_users');
		$defaultUserGroup = $config->get('new_usertype', 2);

		$instance->set('id', 0);
		$instance->set('name', $loginInformation['fullname']);
		$instance->set('username', $loginInformation['username']);
		$instance->set('email', $loginInformation['email']);
		$instance->set('usertype', 'deprecated');
		$instance->set('groups', [$defaultUserGroup]);

		return $instance;
	}
}