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

		$this->invalidateFiles();

		return true;
	}

	private function invalidateFiles()
	{
		function getManifestXML($class): ?SimpleXMLElement
		{
			// Get the package element name
			$myPackage = strtolower(str_replace('InstallerScript', '', $class));

			// Get the package's manifest file
			$filePath = JPATH_MANIFESTS . '/packages/' . $myPackage . '.xml';

			if (!@file_exists($filePath) || !@is_readable($filePath))
			{
				return null;
			}

			$xmlContent = @file_get_contents($filePath);

			if (empty($xmlContent))
			{
				return null;
			}

			return new SimpleXMLElement($xmlContent);
		}

		function xmlNodeToExtensionName(SimpleXMLElement $fileField): ?string
		{
			$type = (string) $fileField->attributes()->type;
			$id   = (string) $fileField->attributes()->id;

			switch ($type)
			{
				case 'component':
				case 'file':
				case 'library':
					$extension = $id;
					break;

				case 'plugin':
					$group     = (string) $fileField->attributes()->group ?? 'system';
					$extension = 'plg_' . $group . '_' . $id;
					break;

				case 'module':
					$client    = (string) $fileField->attributes()->client ?? 'site';
					$extension = (($client != 'site') ? 'a' : '') . $id;
					break;

				default:
					$extension = null;
					break;
			}

			return $extension;
		}

		function getExtensionsFromManifest(?SimpleXMLElement $xml): array{
			if (empty($xml))
			{
				return [];
			}

			$extensions = [];

			foreach ($xml->xpath('//files/file') as $fileField)
			{
				$extensions[] = xmlNodeToExtensionName($fileField);
			}

			return array_filter($extensions);
		}

		function clearFileInOPCache(string $file): bool
		{
			static $hasOpCache = null;

			if (is_null($hasOpCache)) {
				$hasOpCache = ini_get('opcache.enable')
				              && function_exists('opcache_invalidate')
				              && (!ini_get('opcache.restrict_api') || stripos(realpath($_SERVER['SCRIPT_FILENAME']), ini_get('opcache.restrict_api')) === 0);
			}

			if ($hasOpCache && (strtolower(substr($file, -4)) === '.php')) {
				$ret = opcache_invalidate($file, true);

				@clearstatcache($file);

				return $ret;
			}

			return false;
		}

		function recursiveClearCache(string $path): void
		{
			if (!@is_dir($path))
			{
				return;
			}

			/** @var DirectoryIterator $file */
			foreach (new DirectoryIterator($path) as $file)
			{
				if ($file->isDot() || $file->isLink()) {
					continue;
				}

				if ($file->isDir())
				{
					recursiveClearCache($file->getPathname());

					continue;
				}

				if (!$file->isFile())
				{
					continue;
				}

				clearFileInOPCache($file->getPathname());
			}
		}

		$extensionsFromPackage = getExtensionsFromManifest(getManifestXML(__CLASS__));

		foreach ($extensionsFromPackage as $element)
		{
			if (strpos($element, 'plg_') !== 0)
			{
				continue;
			}

			[$dummy, $folder, $plugin] = explode('_', $element);

			recursiveClearCache(
				sprintf(
					'%s/%s/%s/services',
					JPATH_PLUGINS, $folder, $plugin
				)
			);

			recursiveClearCache(
				sprintf(
					'%s/%s/%s/src',
					JPATH_PLUGINS, $folder, $plugin
				)
			);
		}

		clearFileInOPCache(JPATH_CACHE . '/autoload_psr4.php');
	}
}