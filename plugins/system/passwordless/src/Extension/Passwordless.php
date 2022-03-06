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
use Joomla\Plugin\System\Passwordless\Extension\Traits\AjaxHandler;
use Joomla\Plugin\System\Passwordless\Extension\Traits\AjaxHandlerChallenge;
use Joomla\Plugin\System\Passwordless\Extension\Traits\AjaxHandlerCreate;
use Joomla\Plugin\System\Passwordless\Extension\Traits\AjaxHandlerDelete;
use Joomla\Plugin\System\Passwordless\Extension\Traits\AjaxHandlerLogin;
use Joomla\Plugin\System\Passwordless\Extension\Traits\AjaxHandlerSaveLabel;
use Joomla\Plugin\System\Passwordless\Extension\Traits\ButtonsInModules;
use Joomla\Plugin\System\Passwordless\Extension\Traits\UserDeletion;
use Joomla\Plugin\System\Passwordless\Extension\Traits\UserHandleCookie;
use Joomla\Plugin\System\Passwordless\Extension\Traits\UserProfileFields;
use Throwable;

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

	// AJAX request handlers
	use AjaxHandler;
	use AjaxHandlerCreate;
	use AjaxHandlerSaveLabel;
	use AjaxHandlerDelete;
	use AjaxHandlerChallenge;
	use AjaxHandlerLogin;

	// Cookies for user handle (truly passwordless flow)
	use UserHandleCookie;

	// Custom user profile fields
	use UserProfileFields;

	// Handle user profile deletion
	use UserDeletion;

	// Add Webauthn buttons
	use ButtonsInModules;

	/**
	 * Constructor. Registers a custom logger.
	 *
	 * @param   DispatcherInterface  &$subject  The object to observe
	 * @param   array                 $config   An optional associative array of configuration settings.
	 *                                          Recognized key values include 'name', 'group', 'params', 'language'
	 *                                          (this list is not meant to be comprehensive).
	 */
	public function __construct($subject, array $config = [])
	{
		parent::__construct($subject, $config);

		Log::addLogger([
			'text_file'         => "plg_system_passwordless.php",
			'text_entry_format' => '{DATETIME}	{PRIORITY} {CLIENTIP}	{MESSAGE}',
		], Log::ALL, [
			"plg_system_passwordless",
		]);
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
			'onAfterInitialise'           => 'onAfterInitialise',
			'onAjaxPasswordless'          => 'onAjaxPasswordless',
			'onAjaxPasswordlessChallenge' => 'onAjaxPasswordlessChallenge',
			'onAjaxPasswordlessCreate'    => 'onAjaxPasswordlessCreate',
			'onAjaxPasswordlessDelete'    => 'onAjaxPasswordlessDelete',
			'onAjaxPasswordlessLogin'     => 'onAjaxPasswordlessLogin',
			'onAjaxPasswordlessSavelabel' => 'onAjaxPasswordlessSavelabel',
			'onUserLoginButtons'          => 'onUserLoginButtons',
			'onUserAfterDelete'           => 'onUserAfterDelete',
			'onContentPrepareForm'        => 'onContentPrepareForm',
		];
	}

	public function onAfterInitialise()
	{
		try
		{
			$this->onAfterInitialiseCookie();
		}
		catch (Throwable $e)
		{
			return;
		}

		try
		{
			$this->onAfterInitialiseAjax();
		}
		catch (Throwable $e)
		{
			return;
		}
	}
}
