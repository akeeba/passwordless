<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Joomla\Plugin\System\Passwordless\Extension;

use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\Database\DatabaseDriver;
use Joomla\Event\DispatcherInterface;
use Joomla\Event\SubscriberInterface;
use Joomla\Plugin\System\Passwordless\Authentication;
use Joomla\Plugin\System\Passwordless\PluginTraits\AdditionalLoginButtons;
use Joomla\Plugin\System\Passwordless\PluginTraits\AjaxHandler;
use Joomla\Plugin\System\Passwordless\PluginTraits\AjaxHandlerChallenge;
use Joomla\Plugin\System\Passwordless\PluginTraits\AjaxHandlerCreate;
use Joomla\Plugin\System\Passwordless\PluginTraits\AjaxHandlerDelete;
use Joomla\Plugin\System\Passwordless\PluginTraits\AjaxHandlerInitCreate;
use Joomla\Plugin\System\Passwordless\PluginTraits\AjaxHandlerLogin;
use Joomla\Plugin\System\Passwordless\PluginTraits\AjaxHandlerSaveLabel;
use Joomla\Plugin\System\Passwordless\PluginTraits\EventReturnAware;
use Joomla\Plugin\System\Passwordless\PluginTraits\UserDeletion;
use Joomla\Plugin\System\Passwordless\PluginTraits\UserLogin;
use Joomla\Plugin\System\Passwordless\PluginTraits\UserProfileFields;

// Protect from unauthorized access
defined('_JEXEC') or die();

/**
 * Akeeba Passwordless Login plugin providing Webauthn integration.
 *
 * The plugin features are broken down into Traits for the sole purpose of making an otherwise supermassive class
 * somewhat manageable.
 *
 * @since 1.0.0
 */
class Passwordless extends CMSPlugin implements SubscriberInterface
{
	/**
	 * The CMS application we are running in
	 *
	 * @var   CMSApplication
	 * @since 1.0.0
	 */
	protected $app;

	/**
	 * The application's database driver object
	 *
	 * @var   DatabaseDriver
	 * @since 1.0.0
	 */
	protected $db;

	/**
	 * Autoload the language files
	 *
	 * @var    boolean
	 * @since  1.0.0
	 */
	protected $autoloadLanguage = true;

	/**
	 * Should I try to detect and register legacy event listeners?
	 *
	 * @var    boolean
	 * @since  2.0.0
	 */
	protected $allowLegacyListeners = false;

	/**
	 * The WebAuthn authentication helper object
	 *
	 * @var   Authentication
	 * @since 2.0.0
	 */
	protected $authenticationHelper;

	// AJAX request handlers
	use AjaxHandler;
	use AjaxHandlerInitCreate;
	use AjaxHandlerCreate;
	use AjaxHandlerSaveLabel;
	use AjaxHandlerDelete;
	use AjaxHandlerChallenge;
	use AjaxHandlerLogin;

	// Custom user profile fields
	use UserProfileFields;

	// Handle user profile deletion
	use UserDeletion;

	// Prevent password login for passwordless users
	use UserLogin;

	// Add Webauthn buttons
	use AdditionalLoginButtons;

	// Utility methods for setting the events' return values
	use EventReturnAware;

	/**
	 * Constructor. Registers a custom logger.
	 *
	 * @param   DispatcherInterface  &$subject  The object to observe
	 * @param   array                 $config   An optional associative array of configuration settings.
	 *                                          Recognized key values include 'name', 'group', 'params', 'language'
	 *                                          (this list is not meant to be comprehensive).
	 */
	public function __construct($subject, array $config = [], Authentication $authHelper = null)
	{
		parent::__construct($subject, $config);

		// Register a debug log file writer
		$logLevels = Log::ERROR | Log::CRITICAL | Log::ALERT | Log::EMERGENCY;

		if (\defined('JDEBUG') && JDEBUG)
		{
			$logLevels = Log::ALL;
		}

		Log::addLogger([
			'text_file'         => "plg_system_passwordless.php",
			'text_entry_format' => '{DATETIME}	{PRIORITY} {CLIENTIP}	{MESSAGE}',
		], $logLevels, ["plg_system_passwordless",]);

		$this->authenticationHelper = $authHelper ?? (new Authentication);
		$this->authenticationHelper->setAttestationSupport($this->params->get('attestationSupport', 1) == 1);
	}

	/**
	 * Returns the Authentication helper object
	 *
	 * @return Authentication
	 *
	 * @since  2.0.0
	 */
	public function getAuthenticationHelper(): Authentication
	{
		return $this->authenticationHelper;
	}

	public static function getSubscribedEvents(): array
	{
		try
		{
			$app = Factory::getApplication();
		}
		catch (\Exception $e)
		{
			return [];
		}

		if ($app->isClient('site') || $app->isClient('administrator') || $app->isClient('cli'))
		{
			require_once __DIR__ . '/../../vendor/autoload.php';
		}

		if (!$app->isClient('site') && !$app->isClient('administrator'))
		{
			return [];
		}

		return [
			'onAjaxPasswordless'           => 'onAjaxPasswordless',
			'onAjaxPasswordlessChallenge'  => 'onAjaxPasswordlessChallenge',
			'onAjaxPasswordlessCreate'     => 'onAjaxPasswordlessCreate',
			'onAjaxPasswordlessDelete'     => 'onAjaxPasswordlessDelete',
			'onAjaxPasswordlessInitcreate' => 'onAjaxPasswordlessInitcreate',
			'onAjaxPasswordlessLogin'      => 'onAjaxPasswordlessLogin',
			'onAjaxPasswordlessSavelabel'  => 'onAjaxPasswordlessSavelabel',
			'onContentPrepareData'         => 'onContentPrepareData',
			'onContentPrepareForm'         => 'onContentPrepareForm',
			'onUserAfterDelete'            => 'onUserAfterDelete',
			'onUserAfterSave'              => 'onUserAfterSave',
			'onUserLogin'                  => 'onUserLogin',
			'onUserLoginButtons'           => 'onUserLoginButtons',
			'onUserLoginFailure'           => 'onUserLoginFailure',
		];
	}
}
