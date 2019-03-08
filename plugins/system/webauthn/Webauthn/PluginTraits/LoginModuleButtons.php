<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Passwordless\Webauthn\PluginTraits;

use Akeeba\Passwordless\Webauthn\Helper\Joomla;
use Exception;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Uri\Uri;

// Protect from unauthorized access
defined('_JEXEC') or die();

/**
 * Inserts Webauthn buttons into login modules
 */
trait LoginModuleButtons
{
	/**
	 * The names of the login modules to intercept. Default: mod_login
	 *
	 * @var   array
	 */
	protected $loginModules = array('mod_login');

	/**
	 * Should I intercept the login page of com_users and add passwordless login buttons there? User configurable.
	 *
	 * @var   bool
	 */
	protected $interceptLogin = true;

	/**
	 * Do I need to I inject buttons? Automatically detected (i.e. disabled if I'm already logged in).
	 *
	 * @var   bool
	 */
	private $needButtonInjection = null;

	/**
	 * Have I already injected CSS and JavaScript? Prevents double inclusion of the same files.
	 *
	 * @var   bool
	 */
	protected $injectedCSSandJS = false;

	/**
	 * Set up the login module button injection feature.
	 *
	 * @return  void
	 */
	protected function setup(): void
	{
		// Don't try to set up this feature if we are alraedy logged in
		if (!$this->isButtonInjectionNecessary())
		{
			return;
		}

		// Don't try to set up this feature if we can't figure out if this is a front- or backend page.
		try
		{
			$isAdminPage = Joomla::isAdminPage();
		}
		catch (Exception $e)
		{
			$this->needButtonInjection = false;

			return;
		}

		$loginModulesParameter = $isAdminPage ? 'backendloginmodules' : 'loginmodules';
		$defaultModules        = $isAdminPage ? 'none' : 'mod_login';
		$loginModules          = $this->params->get($loginModulesParameter);
		$loginModules          = trim($loginModules);
		$loginModules          = empty($loginModules) ? $defaultModules : $loginModules;
		$loginModules          = explode(',', $loginModules);
		$this->loginModules    = array_map('trim', $loginModules);

		// Load the plugin options into properties
		$this->interceptLogin = $this->params->get('interceptlogin', 1);
		$this->useCustomCSS   = $this->params->get('customcss', true);
		$this->iconClass      = $this->params->get('icon_class', '');
	}

	/**
	 * Should I enable the substitutions performed by this plugin?
	 *
	 * @return  bool
	 */
	private function isButtonInjectionNecessary(): bool
	{
		if (is_null($this->needButtonInjection))
		{
			$this->needButtonInjection = true;

			if (!Joomla::getUser()->guest)
			{
				$this->needButtonInjection = false;
			}
		}

		return $this->needButtonInjection;
	}

	/**
	 * Intercepts module rendering, appending the Webauthn button to the configured login module.
	 *
	 * @param   object  $module   The module being rendered
	 * @param   object  $attribs  The module rendering attributes
	 *
	 * @throws  Exception
	 */
	public function onRenderModule(&$module, &$attribs): void
	{
		if (!$this->isButtonInjectionNecessary())
		{
			return;
		}

		// We need this convoluted check because the JDocument is not initialized on plugin object construction or even
		// during onAfterInitialize. This is the only safe way to determine the document type.
		static $docType = null;

		if (is_null($docType))
		{
			try
			{
				$document = Joomla::getApplication()->getDocument();
			}
			catch (Exception $e)
			{
				$document = null;
			}

			$docType = (is_null($document)) ? 'error' : $document->getType();

			if ($docType != 'html')
			{
				$this->needButtonInjection = false;

				return;
			}
		}

		// If it's not a module I need to intercept bail out
		if (!in_array($module->module, $this->loginModules))
		{
			return;
		}

		// Append the passwordless login buttons content to the login module
		Joomla::log('system', "Injecting Webauthn passwordless login buttons to {$module->module} module.");
		$this->injectLoginCSSAndJavascript();
		$module->content .= Joomla::renderLayout('akeeba.webauthn.button', []);
	}

	/**
	 * Injects the Webauthn CSS and Javascript for frontend logins, but only once per page load.
	 *
	 * @return  void
	 */
	protected function injectLoginCSSAndJavascript(): void
	{
		if ($this->injectedCSSandJS)
		{
			return;
		}

		// Load the CSS
		HTMLHelper::_('stylesheet', 'plg_system_webauthn/button.css', [
			'relative' => true,
		]);

		// Load the JavaScript
		HTMLHelper::_('script', 'plg_system_webauthn/login.js', [
			'relative'  => true,
			'framework' => true,
		]);

		// Load language strings client-side
		Text::script('PLG_SYSTEM_WEBAUTHN_ERR_CANNOT_FIND_USERNAME');
		Text::script('PLG_SYSTEM_WEBAUTHN_ERR_EMPTY_USERNAME');

		// Store the current URL as the return URL after login (or failure)
		Joomla::setSessionVar('returnUrl', Uri::current(), 'plg_system_webauthn');

		// Set the "don't load again" flag
		$this->injectedCSSandJS = true;
	}
}