<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2021 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Passwordless\Helper;

// Protect from unauthorized access
defined('_JEXEC') or die();

use DateTimeZone;
use Exception;
use JDatabaseDriver;
use JEventDispatcher;
use Joomla\CMS\Application\CliApplication;
use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Date\Date;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Layout\FileLayout;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Session\Session;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\CMS\User\UserHelper;
use Joomla\Registry\Registry;
use RuntimeException;

/**
 * A helper class for abstracting core features in Joomla! 3.4 and later, including 4.x
 */
abstract class Joomla
{
	/**
	 * A fake session storage for CLI apps. Since CLI applications cannot have a session we are using a Registry object
	 * we manage internally.
	 *
	 * @var   Registry
	 * @since 1.0.0
	 */
	protected static $fakeSession = null;

	/**
	 * Are we inside the administrator application
	 *
	 * @var   bool
	 * @since 1.0.0
	 */
	protected static $isAdmin = null;

	/**
	 * Are we inside a CLI application
	 *
	 * @var   bool
	 * @since 1.0.0
	 */
	protected static $isCli = null;

	/**
	 * Which plugins have already registered a text file logger. Prevents double registration of a log file.
	 *
	 * @var   array
	 * @since 1.0.0
	 */
	protected static $registeredLoggers = [];

	/**
	 * Are we inside an administrator page?
	 *
	 * @param   CMSApplication  $app  The current CMS application which tells us if we are inside an admin page
	 *
	 * @return  bool
	 *
	 * @throws  Exception
	 *
	 * @since   1.0.0
	 */
	public static function isAdminPage(CMSApplication $app = null): bool
	{
		if (is_null(self::$isAdmin))
		{
			if (is_null($app))
			{
				$app = self::getApplication();
			}

			self::$isAdmin = $app->isClient('administrator');
		}

		return self::$isAdmin;
	}

	/**
	 * Are we inside a CLI application
	 *
	 * @param   CMSApplication  $app  The current CMS application which tells us if we are inside an admin page
	 *
	 * @return  bool
	 *
	 * @since   1.0.0
	 */
	public static function isCli(CMSApplication $app = null): bool
	{
		if (is_null(self::$isCli))
		{
			if (is_null($app))
			{
				try
				{
					$app = self::getApplication();
				}
				catch (Exception $e)
				{
					$app = null;
				}
			}

			if (is_null($app))
			{
				self::$isCli = true;
			}

			if (is_object($app))
			{
				self::$isCli = $app instanceof \Exception;

				if (class_exists('Joomla\\CMS\\Application\\CliApplication'))
				{
					self::$isCli = self::$isCli || $app instanceof CliApplication;
				}
			}
		}

		return self::$isCli;
	}

	/**
	 * Is the current user allowed to edit the social login configuration of $user? To do so I must either be editing my
	 * own account OR I have to be a Super User.
	 *
	 * @param   ?User  $user  The user you want to know if we're allowed to edit
	 *
	 * @return  bool
	 *
	 * @since   1.0.0
	 */
	public static function canEditUser(?User $user = null): bool
	{
		// I can edit myself
		if (empty($user))
		{
			return true;
		}

		// Guests can't have social logins associated
		if ($user->guest)
		{
			return false;
		}

		// Get the currently logged in used
		$myUser = self::getUser();

		// Same user? I can edit myself
		if ($myUser->id == $user->id)
		{
			return true;
		}

		// To edit a different user I must be a Super User myself. If I'm not, I can't edit another user!
		if (!$myUser->authorise('core.admin'))
		{
			return false;
		}

		// I am a Super User editing another user. That's allowed.
		return true;
	}

	/**
	 * Helper method to render a JLayout.
	 *
	 * @param   string   $layoutFile   Dot separated path to the layout file, relative to base path
	 *                                 (plugins/system/passwordless/layout)
	 * @param   ?object  $displayData  Object which properties are used inside the layout file to build displayed
	 *                                 output
	 * @param   string   $includePath  Additional path holding layout files
	 * @param   mixed    $options      Optional custom options to load. Registry or array format. Set 'debug'=>true to
	 *                                 output debug information.
	 *
	 * @return  string
	 *
	 * @since   1.0.0
	 */
	public static function renderLayout(string $layoutFile, $displayData = null, string $includePath = '', array $options = []): string
	{
		$basePath = JPATH_SITE . '/plugins/system/passwordless/layout';
		$layout   = new FileLayout($layoutFile, $basePath, $options);

		if (!empty($includePath))
		{
			$layout->addIncludePath($includePath);
		}

		return $layout->render($displayData);
	}

	/**
	 * Execute a plugin event and return the results
	 *
	 * @param   string           $event   The plugin event to trigger.
	 * @param   array            $data    The data to pass to the event handlers.
	 * @param   ?CMSApplication  $app     The application to run plugins against,
	 *                                    default the currently loaded application.
	 *
	 * @return  array  The plugin responses
	 *
	 * @throws  RuntimeException  When we cannot run the plugins
	 * @throws  Exception         When we cannot create the application
	 *
	 * @since   1.0.0
	 */
	public static function runPlugins(string $event, array $data, $app = null): array
	{
		if (!is_object($app))
		{
			$app = self::getApplication();
		}

		if (method_exists($app, 'triggerEvent'))
		{
			return $app->triggerEvent($event, $data);
		}

		if (class_exists('JEventDispatcher'))
		{
			return JEventDispatcher::getInstance()->trigger($event, $data);
		}

		throw new RuntimeException('Cannot run plugins');
	}

	/**
	 * Get the CMS application object
	 *
	 * @return  CMSApplication
	 *
	 * @throws  Exception
	 *
	 * @since   1.0.0
	 */
	public static function getApplication(): CMSApplication
	{
		$app = Factory::getApplication();

		if (self::isCmsApplication($app))
		{
			return $app;
		}

		throw new RuntimeException('Cannot find a valid CMS application object');
	}

	/**
	 * Returns the user, delegates to JFactory/Factory.
	 *
	 * @param   int|null  $id  The ID of the Joomla! user to load, default null (currently logged in user)
	 *
	 * @return  User
	 *
	 * @since   1.0.0
	 */
	public static function getUser(?int $id = null): ?User
	{
		if (version_compare(JVERSION, '3.999.999', 'le'))
		{
			return Factory::getUser($id);
		}

		if (is_null($id))
		{
			return Factory::getApplication()->getIdentity();
		}

		return Factory::getContainer()->get(UserFactoryInterface::class)->loadUserById($id);
	}

	/**
	 * Set a variable in the user session
	 *
	 * @param   string   $name       The name of the variable to set
	 * @param   ?string  $value      (optional) The value to set it to, default is null
	 * @param   string   $namespace  (optional) The variable's namespace e.g. the component name. Default: 'default'
	 *
	 * @return  void
	 *
	 * @since   1.0.0
	 */
	public static function setSessionVar(string $name, ?string $value = null, string $namespace = 'default'): void
	{
		$qualifiedKey = "$namespace.$name";

		if (self::isCli())
		{
			self::getFakeSession()->set($qualifiedKey, $value);

			return;
		}

		if (version_compare(JVERSION, '3.99999.99999', 'lt'))
		{
			self::getSession()->set($name, $value, $namespace);

			return;
		}

		if (empty($namespace))
		{
			self::getSession()->set($name, $value);
		}

		$registry = self::getSession()->get('registry');

		if (is_null($registry))
		{
			$registry = new Registry();

			self::getSession()->set('registry', $registry);
		}

		$registry->set($qualifiedKey, $value);
	}

	/**
	 * Get a variable from the user session
	 *
	 * @param   string   $name       The name of the variable to set
	 * @param   ?string  $default    (optional) The default value to return if the variable does not exit, default: null
	 * @param   string   $namespace  (optional) The variable's namespace e.g. the component name. Default: 'default'
	 *
	 * @return  mixed
	 *
	 * @since   1.0.0
	 */
	public static function getSessionVar(string $name, ?string $default = null, string $namespace = 'default')
	{
		$qualifiedKey = "$namespace.$name";

		if (self::isCli())
		{
			return self::getFakeSession()->get("$namespace.$name", $default);
		}

		if (version_compare(JVERSION, '3.99999.99999', 'lt'))
		{
			return self::getSession()->get($name, $default, $namespace);
		}

		if (empty($namespace))
		{
			return self::getSession()->get($name, $default);
		}

		$registry = self::getSession()->get('registry');

		if (is_null($registry))
		{
			$registry = new Registry();

			self::getSession()->set('registry', $registry);
		}

		return $registry->get($qualifiedKey, $default);
	}

	/**
	 * Unset a variable from the user session
	 *
	 * @param   string  $name       The name of the variable to unset
	 * @param   string  $namespace  (optional) The variable's namespace e.g. the component name. Default: 'default'
	 *
	 * @return  void
	 *
	 * @since   1.0.0
	 */
	public static function unsetSessionVar(string $name, string $namespace = 'default'): void
	{
		self::setSessionVar($name, null, $namespace);
	}

	/**
	 * Return the session token. Two types of tokens can be returned:
	 *
	 * @return  mixed
	 *
	 * @since   1.0.0
	 */
	public static function getToken(): string
	{
		// For CLI apps we implement our own fake token system
		if (self::isCli())
		{
			$token = self::getSessionVar('session.token');

			// Create a token
			if (is_null($token))
			{
				$token = UserHelper::genRandomPassword(32);

				self::setSessionVar('session.token', $token);
			}

			return (string) $token;
		}

		// Web application, go through the regular Joomla! API.
		return self::getSession()->getToken();
	}

	/**
	 * Is the variable an CMS application object?
	 *
	 * @param   mixed  $app
	 *
	 * @return  bool
	 *
	 * @since   1.0.0
	 */
	public static function isCmsApplication($app): bool
	{
		if (!is_object($app))
		{
			return false;
		}

		return $app instanceof CMSApplication;
	}

	/**
	 * Get the Joomla! database driver object
	 *
	 * @return  JDatabaseDriver
	 *
	 * @since   1.0.0
	 */
	public static function getDbo(): JDatabaseDriver
	{
		return Factory::getDbo();
	}

	/**
	 * Get the Joomla! global configuration object
	 *
	 * @return  Registry
	 *
	 * @since   1.0.0
	 */
	public static function getConfig(): Registry
	{
		return Factory::getConfig();
	}

	/**
	 * Writes a log message to the debug log
	 *
	 * @param   string  $plugin    The Social Login plugin which generated this log message
	 * @param   string  $message   The message to write to the log
	 * @param   int     $priority  Log message priority, default is Log::DEBUG
	 *
	 * @return  void
	 *
	 * @since   1.0.0
	 */
	public static function log(string $plugin, string $message, $priority = Log::DEBUG): void
	{
		Log::add($message, $priority, 'passwordless.' . $plugin);
	}

	/**
	 * Register a debug log file writer for a Social Login plugin.
	 *
	 * @param   string  $plugin  The Social Login plugin for which to register a debug log file writer
	 *
	 * @return  void
	 *
	 * @since   1.0.0
	 */
	public static function addLogger(string $plugin): void
	{
		// Make sure this logger is not already registered
		if (in_array($plugin, self::$registeredLoggers))
		{
			return;
		}

		self::$registeredLoggers[] = $plugin;

		// We only log errors unless Site Debug is enabled
		$logLevels = Log::ERROR | Log::CRITICAL | Log::ALERT | Log::EMERGENCY;

		if (defined('JDEBUG') && JDEBUG)
		{
			$logLevels = Log::ALL;
		}

		// Add a formatted text logger
		Log::addLogger([
			'text_file'         => "passwordless_{$plugin}.php",
			'text_entry_format' => '{DATETIME}	{PRIORITY} {CLIENTIP}	{MESSAGE}',
		], $logLevels, [
			"passwordless.{$plugin}",
		]);
	}

	/**
	 * Format a date for display.
	 *
	 * The $tzAware parameter defines whether the formatted date will be timezone-aware. If set to false the formatted
	 * date will be rendered in the UTC timezone. If set to true the code will automatically try to use the logged in
	 * user's timezone or, if none is set, the site's default timezone (Server Timezone). If set to a positive integer
	 * the same thing will happen but for the specified user ID instead of the currently logged in user.
	 *
	 * @param   string|\DateTime  $date     The date to format
	 * @param   string            $format   The format string, default is Joomla's DATE_FORMAT_LC6 (usually "Y-m-d
	 *                                      H:i:s")
	 * @param   bool|int          $tzAware  Should the format be timezone aware? See notes above.
	 *
	 * @return  string
	 */
	public static function formatDate($date, ?string $format = null, bool $tzAware = true): string
	{
		$utcTimeZone = new DateTimeZone('UTC');
		$jDate       = new Date($date, $utcTimeZone);

		// Which timezone should I use?
		$tz = null;

		if ($tzAware !== false)
		{
			$userId = is_bool($tzAware) ? null : (int) $tzAware;

			try
			{
				$tzDefault = Factory::getApplication()->get('offset');
			}
			catch (\Exception $e)
			{
				$tzDefault = 'GMT';
			}

			$user = Factory::getUser($userId);
			$tz   = $user->getParam('timezone', $tzDefault);
		}

		if (!empty($tz))
		{
			try
			{
				$userTimeZone = new DateTimeZone($tz);

				$jDate->setTimezone($userTimeZone);
			}
			catch (\Exception $e)
			{
				// Nothing. Fall back to UTC.
			}
		}

		if (empty($format))
		{
			$format = Text::_('DATE_FORMAT_LC6');
		}

		return $jDate->format($format, true);
	}

	/**
	 * Get the Joomla! session
	 *
	 * @return  Session
	 *
	 * @since   1.0.0
	 */
	protected static function getSession(): Session
	{
		return Factory::getSession();
	}

	/**
	 * Get a fake session registry for CLI applications
	 *
	 * @return  Registry
	 *
	 * @since   1.0.0
	 */
	protected static function getFakeSession(): Registry
	{
		if (!is_object(self::$fakeSession))
		{
			self::$fakeSession = new Registry();
		}

		return self::$fakeSession;
	}
}
