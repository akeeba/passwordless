<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Joomla\Plugin\System\Passwordless\PluginTraits;

// Protect from unauthorized access
defined('_JEXEC') or die();

use Exception;
use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Document\HtmlDocument;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\UserHelper;
use Joomla\Event\Event;

/**
 * Inserts Webauthn buttons into login modules
 */
trait AdditionalLoginButtons
{
	/**
	 * Do I need to inject buttons? Automatically detected (i.e. disabled if I'm already logged
	 * in).
	 *
	 * @var     boolean|null
	 * @since   1.0.0
	 */
	protected $allowButtonDisplay = null;

	/**
	 * Have I already injected CSS and JavaScript? Prevents double inclusion of the same files.
	 *
	 * @var     boolean
	 * @since   1.0.0
	 */
	private $injectedCSSandJS = false;

	/**
	 * Creates additional login buttons
	 *
	 * @return  void
	 *
	 * @throws  Exception
	 *
	 * @see     AuthenticationHelper::getLoginButtons()
	 *
	 * @since   1.0.0
	 */
	public function onUserLoginButtons(Event $event): void
	{
		/** @var string $form The HTML ID of the form we are enclosed in */
		[$form] = $event->getArguments();

		// If we determined we should not inject a button return early
		if (!$this->mustDisplayButton())
		{
			return;
		}

		// Append the social login buttons content
		$this->addLoginCSSAndJavascript();

		$randomId = 'akpwl-login-' . UserHelper::genRandomPassword(12) . '-' . UserHelper::genRandomPassword(8);

		// Get local path to image
		$imgName = $this->app->isClient('administrator') ? 'passkey-white.svg' : 'passkey.svg';
		$image   = HTMLHelper::_('image', 'plg_system_passwordless/' . $imgName, '', '', true, true);

		// If you can't find the image then skip it
		$image = $image ? JPATH_ROOT . substr($image, \strlen(Uri::root(true))) : '';

		// Extract image if it exists
		$image = file_exists($image) ? file_get_contents($image) : '';

		$this->returnFromEvent($event, [
			[
				'label'                  => 'PLG_SYSTEM_PASSWORDLESS_LOGIN_LABEL',
				'tooltip'                => 'PLG_SYSTEM_PASSWORDLESS_LOGIN_DESC',
				'id'                     => $randomId,
				'data-passwordless-form' => $form,
				'svg'                    => $image,
				'class'                  => 'plg_system_passwordless_login_button',
			],
		]);
	}

	/**
	 * Injects the Webauthn CSS and Javascript for frontend logins, but only once per page load.
	 *
	 * @return  void
	 */
	private function addLoginCSSAndJavascript(): void
	{
		if ($this->injectedCSSandJS)
		{
			return;
		}

		$this->injectedCSSandJS = true;

		if (!($this->app instanceof CMSApplication))
		{
			return;
		}

		$document = $this->app->getDocument();

		if (!($document instanceof HtmlDocument))
		{
			return;
		}

		$wa       = $document->getWebAssetManager();
		$wa->getRegistry()->addExtensionRegistryFile('plg_system_passwordless');
		$wa->useScript('plg_system_passwordless.login');

		// Load language strings client-side
		Text::script('PLG_SYSTEM_PASSWORDLESS_ERR_CANNOT_FIND_USERNAME');
		Text::script('PLG_SYSTEM_PASSWORDLESS_ERR_INVALID_USERNAME');
		Text::script('PLG_SYSTEM_PASSWORDLESS_ERR_EMPTY_USERNAME');

		// Store the current URL as the default return URL after login (or failure)
		$this->app->getSession()->set('plg_system_passwordless.returnUrl', Uri::current());
	}

	/**
	 * Should I allow this plugin to add a WebAuthn login button?
	 *
	 * @return  boolean
	 *
	 * @since   1.0.0
	 */
	private function mustDisplayButton(): bool
	{
		// We must have a valid application
		if (!($this->app instanceof CMSApplication))
		{
			return false;
		}

		// This plugin only applies to the frontend and administrator applications
		if (!$this->app->isClient('site') && !$this->app->isClient('administrator'))
		{
			return false;
		}

		// We must have a valid user
		if (empty($this->app->getIdentity()))
		{
			return false;
		}

		if (\is_null($this->allowButtonDisplay))
		{
			$this->allowButtonDisplay = false;

			/**
			 * Do not add a WebAuthn login button if we are already logged in
			 */
			if (!$this->app->getIdentity()->guest)
			{
				return false;
			}

			/**
			 * Only display a button on HTML output
			 */
			try
			{
				$document = $this->app->getDocument();
			}
			catch (Exception $e)
			{
				$document = null;
			}

			if (!($document instanceof HtmlDocument))
			{
				return false;
			}

			/**
			 * WebAuthn only works on HTTPS. This is a security-related limitation of the W3C Web Authentication
			 * specification, not an issue with this plugin :)
			 */
			if (!Uri::getInstance()->isSsl())
			{
				return false;
			}

			// All checks passed; we should allow displaying a WebAuthn login button
			$this->allowButtonDisplay = true;
		}

		return $this->allowButtonDisplay;
	}

}