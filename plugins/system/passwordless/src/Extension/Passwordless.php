<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Plugin\System\Passwordless\Extension;

use Akeeba\Plugin\System\Passwordless\Authentication\AuthenticationInterface;
use Akeeba\Plugin\System\Passwordless\PluginTraits\AdditionalLoginButtons;
use Akeeba\Plugin\System\Passwordless\PluginTraits\AjaxHandler;
use Akeeba\Plugin\System\Passwordless\PluginTraits\AjaxHandlerChallenge;
use Akeeba\Plugin\System\Passwordless\PluginTraits\AjaxHandlerCreate;
use Akeeba\Plugin\System\Passwordless\PluginTraits\AjaxHandlerDelete;
use Akeeba\Plugin\System\Passwordless\PluginTraits\AjaxHandlerInitCreate;
use Akeeba\Plugin\System\Passwordless\PluginTraits\AjaxHandlerLogin;
use Akeeba\Plugin\System\Passwordless\PluginTraits\AjaxHandlerSaveLabel;
use Akeeba\Plugin\System\Passwordless\PluginTraits\EventReturnAware;
use Akeeba\Plugin\System\Passwordless\PluginTraits\Migration;
use Akeeba\Plugin\System\Passwordless\PluginTraits\RunPluginsTrait;
use Akeeba\Plugin\System\Passwordless\PluginTraits\UserDeletion;
use Akeeba\Plugin\System\Passwordless\PluginTraits\UserLogin;
use Akeeba\Plugin\System\Passwordless\PluginTraits\UserProfileFields;
use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\Database\DatabaseAwareInterface;
use Joomla\Database\DatabaseAwareTrait;
use Joomla\Event\SubscriberInterface;

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
class Passwordless extends CMSPlugin implements SubscriberInterface, DatabaseAwareInterface
{
	use DatabaseAwareTrait;

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
	 * @var   AuthenticationInterface
	 * @since 2.0.0
	 */
	protected AuthenticationInterface $authenticationHelper;

	// Utility methods for setting the events' return values
	use EventReturnAware;
	use RunPluginsTrait;

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

	// Migrate settings from Joomla's WebAuthn
	use Migration;

	public function setUpLogging()
	{
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
	}

	public function setAuthenticationHelper(AuthenticationInterface $authHelper): void
	{
		$this->authenticationHelper = $authHelper;
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

		if (!$app->isClient('site') && !$app->isClient('administrator'))
		{
			return [];
		}

		return [
			'onAfterInitialise'            => 'onAfterInitialise',
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

	/**
	 * Returns the Authentication helper object
	 *
	 * @return AuthenticationInterface
	 *
	 * @since  2.0.0
	 */
	public function getAuthenticationHelper(): AuthenticationInterface
	{
		return $this->authenticationHelper;
	}
}
