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
use Joomla\CMS\Log\Log;
use Joomla\Utilities\ArrayHelper;

trait UserDeletion
{
	/**
	 * Remove all passwordless credential information for the given user ID.
	 *
	 * This method is called after user data is deleted from the database.
	 *
	 * @param   array        $user     Holds the user data
	 * @param   bool         $success  True if user was successfully stored in the database
	 * @param   string|null  $msg      Message
	 *
	 * @return  bool
	 *
	 * @since   1.0.0
	 */
	public function onUserAfterDelete(array $user, bool $success, ?string $msg): bool
	{
		if (!$success)
		{
			return false;
		}

		$userId = ArrayHelper::getValue($user, 'id', 0, 'int');

		if ($userId)
		{
			Log::add(Log::INFO, 'plg_system_passwordless', sprintf('Removing Akeeba Passwordless Login information for deleted user #%s', $userId));

			$db    = $this->db;
			$query = $db->getQuery(true)
				->delete($db->qn('#__passwordless_credentials'))
				->where($db->qn('user_id') . ' = ' . $db->q($userId));

			try
			{
				$db->setQuery($query)->execute();
			}
			catch (Exception $e)
			{
				// Suck it.
			}
		}

		return true;
	}
}