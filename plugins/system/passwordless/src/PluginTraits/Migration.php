<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

/**
 * @package     Akeeba\Plugin\System\Passwordless\PluginTraits
 * @subpackage
 *
 * @copyright   A copyright
 * @license     A "Slug" license name e.g. GPL2
 */

namespace Akeeba\Plugin\System\Passwordless\PluginTraits;

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Database\ParameterType;
use Joomla\Event\Event;
use Throwable;

trait Migration
{
	/**
	 * Handles the onAfterInitialize event. We use it to:
	 * - Migrate authenticators from Joomla's plg_system_webauthn plugin
	 *
	 * @param   Event  $e  The event we are handling
	 *
	 * @since   2.0.0
	 */
	public function onAfterInitialise(Event $e)
	{
		if ($this->params->get('joomlaWebauthn', 0) == 1)
		{
			$this->migrateFromWebAuthn();
		}
	}

	/**
	 * Perform the migration process from plg_system_webauthn
	 *
	 * @return  void
	 * @since   2.0.0
	 */
	private function migrateFromWebAuthn(): void
	{
		$this->migrateDatabaseRecords();
		$this->disableWebAuthnPlugin();
		$this->disableMigrationOption();
	}

	/**
	 * Migrate the database records for authenticators
	 *
	 * @return  void
	 * @since   2.0.0
	 */
	private function migrateDatabaseRecords(): void
	{
		$db = $this->db;

		$db->lockTable('#__passwordless_credentials');
		$db->lockTable('#__webauthn_credentials');
		$db->transactionStart();

		$innerQuery = $db->getQuery(true)
		                 ->select($db->quoteName('id'))
		                 ->from($db->quoteName('#__passwordless_credentials'));

		$outerQuery = $db->getQuery(true)
		                 ->select('*')
		                 ->from($db->quoteName("#__webauthn_credentials"))
		                 ->where($db->quoteName('id') . ' NOT IN(' . $innerQuery . ')');

		$tnPasswordless = $db->quoteName('#__passwordless_credentials');
		$query          = <<< SQL
INSERT INTO {$tnPasswordless} {$outerQuery}
SQL;
		$db->setQuery($query)->execute();

		$db->transactionCommit();
		$db->truncateTable('#__webauthn_credentials');

		$db->unlockTables();
	}

	/**
	 * Disable the plg_system_webauthn plugin
	 *
	 * @return  void
	 * @since   2.0.0
	 */
	private function disableWebAuthnPlugin()
	{
		$plugin = PluginHelper::getPlugin('system', 'webauthn');

		if (empty($plugin))
		{
			return;
		}

		$eid = $plugin->id;

		$db    = $this->db;
		$query = $db->getQuery(true)
		            ->update($db->quoteName('#__extensions'))
		            ->set($db->quoteName('enabled') . ' = 0')
		            ->where($db->quoteName('extension_id') . ' = :eid')
		            ->bind(':eid', $eid, ParameterType::INTEGER);
		$db->setQuery($query)->execute();

		// Clear com_plugins cache to effect the change
		$this->clearCacheGroup('com_plugins');
	}

	/**
	 * Forcibly clear the Joomla cache for a specific cache group
	 *
	 * @param   string  $group  The cache group to clear
	 *
	 * @return  void
	 * @since   2.0.0
	 */
	private function clearCacheGroup(string $group): void
	{
		// Get the cache controller's options
		try
		{
			Factory::getContainer()
			       ->get('cache.controller.factory')
			       ->createCacheController('callback', [
				       'defaultgroup' => $group,
				       'cachebase'    => $this->app->get('cache_path', JPATH_CACHE),
				       'result'       => true,
			       ])
				->cache->clean();
		}
		catch (Throwable $e)
		{
			// No problem, just go away
		}
	}

	/**
	 * Disable the migration option in this here plugin
	 *
	 * @return  void
	 * @since   2.0.0
	 */
	private function disableMigrationOption(): void
	{
		$this->params->set('joomlaWebauthn', 0);

		$plugin = PluginHelper::getPlugin($this->_type, $this->_name);
		$eid    = $plugin->id;
		$params = $this->params->toString();
		$db     = $this->db;
		$query  = $db->getQuery(true)
		             ->update($db->quoteName('#__extensions'))
		             ->set($db->quoteName('params') . ' = :params')
		             ->where($db->quoteName('extension_id') . ' = :eid')
		             ->bind(':params', $params)
		             ->bind(':eid', $eid, ParameterType::INTEGER);
		$db->setQuery($query)->execute();

		// Clear com_plugins cache to effect the change
		$this->clearCacheGroup('com_plugins');
	}
}