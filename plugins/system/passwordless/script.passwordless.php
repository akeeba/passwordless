<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2023 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

defined('_JEXEC') || die;

use Joomla\CMS\Installer\Adapter\PluginAdapter;
use Joomla\CMS\Installer\InstallerScript;

class PlgSystemPasswordlessInstallerScript extends InstallerScript
{
	protected $minimumPhp = '7.4';

	protected $minimumJoomla = '4.3';

	/**
	 * @param   string         $type
	 * @param   PluginAdapter  $parent
	 *
	 *
	 * @since version
	 */
	public function postflight($type, $parent)
	{
		if ($type === 'uninstall')
		{
			return true;
		}

		if (class_exists(JNamespacePsr4Map::class))
		{
			try
			{
				$nsMap = new JNamespacePsr4Map();

				@clearstatcache(JPATH_CACHE . '/autoload_psr4.php');

				if (function_exists('opcache_invalidate'))
				{
					@opcache_invalidate(JPATH_CACHE . '/autoload_psr4.php');
				}

				@clearstatcache(JPATH_CACHE . '/autoload_psr4.php');
				$nsMap->create();

				if (function_exists('opcache_invalidate'))
				{
					@opcache_invalidate(JPATH_CACHE . '/autoload_psr4.php');
				}

				$nsMap->load();
			}
			catch (\Throwable $e)
			{
				// In case of failure, just try to delete the old autoload_psr4.php file
				if (function_exists('opcache_invalidate'))
				{
					@opcache_invalidate(JPATH_CACHE . '/autoload_psr4.php');
				}

				@unlink(JPATH_CACHE . '/autoload_psr4.php');
				@clearstatcache(JPATH_CACHE . '/autoload_psr4.php');
			}
		}

		return true;
	}
}