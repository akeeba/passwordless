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
use Joomla\CMS\Log\Log;
use Joomla\Database\ParameterType;
use Joomla\Event\Event;
use Joomla\Utilities\ArrayHelper;

trait UserDeletion
{
	/**
	 * Remove all passwordless credential information for the given user ID.
	 *
	 * This method is called after user data is deleted from the database.
	 *
	 * @return  void
	 *
	 * @since   1.0.0
	 */
	public function onUserAfterDelete(Event $event): void
	{
		/**
		 * @var   array       $user    Holds the user data
		 * @var   bool        $success True if user was successfully stored in the database
		 * @var   string|null $msg     Message
		 */
		[$user, $success, $msg] = $event->getArguments();

		if (!$success)
		{
			$this->returnFromEvent($event, false);

			return;
		}

		$userId = ArrayHelper::getValue($user, 'id', 0, 'int');

		if ($userId)
		{
			Log::add(sprintf('Removing Akeeba Passwordless Login information for deleted user #%s', $userId),  Log::DEBUG, 'plg_system_passwordless');

			$db    = $this->db;
			$query = $db->getQuery(true)
				->delete($db->qn('#__passwordless_credentials'))
				->where($db->qn('user_id') . ' = :userId')
				->bind(':userId', $user, ParameterType::INTEGER);

			try
			{
				$db->setQuery($query)->execute();
			}
			catch (Exception $e)
			{
				// Suck it.
			}

			// Delete user profile information
			$profileKey = 'passwordless.%';
			$query      = $db->getQuery(true)
			                 ->delete($db->quoteName('#__user_profiles'))
			                 ->where($db->quoteName('user_id') . ' = :user_id')
			                 ->where($db->quoteName('profile_key') . ' LIKE :profile_key')
			                 ->bind(':user_id', $userId, ParameterType::INTEGER)
			                 ->bind(':profile_key', $profileKey, ParameterType::STRING);

			try
			{
				$db->setQuery($query)->execute();
			}
			catch (Exception $e)
			{
				// Suck it.
			}
		}

		$this->returnFromEvent($event, true);
	}
}