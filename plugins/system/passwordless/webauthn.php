<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

use Akeeba\Passwordless\Helper\Joomla;
use Akeeba\Passwordless\PluginTraits\AjaxHandler;
use Akeeba\Passwordless\PluginTraits\AjaxHandlerChallenge;
use Akeeba\Passwordless\PluginTraits\AjaxHandlerCreate;
use Akeeba\Passwordless\PluginTraits\AjaxHandlerDelete;
use Akeeba\Passwordless\PluginTraits\AjaxHandlerLogin;
use Akeeba\Passwordless\PluginTraits\AjaxHandlerSaveLabel;
use Akeeba\Passwordless\PluginTraits\ButtonsInModules;
use Akeeba\Passwordless\PluginTraits\ButtonsInUserPage;
use Akeeba\Passwordless\PluginTraits\UserDeletion;
use Akeeba\Passwordless\PluginTraits\UserProfileFields;
use Joomla\CMS\Form\Form;
use Joomla\CMS\Plugin\CMSPlugin;

// Protect from unauthorized access
defined('_JEXEC') or die();

// Register a PSR-4 autoloader for this plugin's classes if necessary
if (!class_exists('Akeeba\\Passwordless\\Helper\\Joomla', true))
{
	JLoader::registerNamespace('Akeeba\\Passwordless', __DIR__ . '/Passwordless', false, false, 'psr4');
}

/**
 * Akeeba Passwordless Login plugin providing Webauthn integration.
 *
 * The plugin features are broken down into Traits for the sole purpose of making an otherwise supermassive class
 * somewhat manageable.
 */
class plgSystemPasswordless extends CMSPlugin
{
	// AJAX request handlers
	use AjaxHandler;
	use AjaxHandlerCreate;
	use AjaxHandlerSaveLabel;
	use AjaxHandlerDelete;
	use AjaxHandlerChallenge;
	use AjaxHandlerLogin;

	// Custom user profile fields
	use UserProfileFields;

	// Handle user profile deletion
	use UserDeletion;

	// Add Webauthn buttons
	use ButtonsInModules;
	use ButtonsInUserPage;

	/**
	 * Constructor. Loads the language files as well.
	 *
	 * @param   object  &$subject  The object to observe
	 * @param   array   $config    An optional associative array of configuration settings.
	 *                             Recognized key values include 'name', 'group', 'params', 'language'
	 *                             (this list is not meant to be comprehensive).
	 */
	public function __construct($subject, array $config = [])
	{
		parent::__construct($subject, $config);

		/**
		 * Note that we cannot load the language at this stage. The application has not been initialized, language
		 * loading won't work in Joomla 4 (even though it works fine in J3). We'll have to load the language
		 * onAfterInitialize instead.
		 */

		// Register a debug log file writer
		Joomla::addLogger('system');

		// Load the Composer autoloader
		require_once __DIR__ . '/vendor/autoload.php';

		// Setup login module interception
		$this->setupLoginModuleButtons();
		$this->setupUserLoginPageButtons();
	}

	/**
	 * My alternative for loadLanguage makes sure that half-translated languages won't result in untranslated strings.
	 *
	 * @param   string  $extension
	 * @param   string  $basePath
	 *
	 * @return bool|void
	 */
	public function loadLanguage($extension = '', $basePath = JPATH_ADMINISTRATOR)
	{
		if (empty($extension))
		{
			$extension = 'plg_' . $this->_type . '_' . $this->_name;
		}

		// Load the language files
		$lang      = \JFactory::getLanguage();
		$lang->load($extension, $basePath, 'en-GB', true, true);
		$lang->load($extension, $basePath, null, true, true);
	}
}
