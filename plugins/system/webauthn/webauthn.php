<?php
/**
 * @package   AkeebaSocialLogin
 * @copyright Copyright (c)2016-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

// Protect from unauthorized access
use Akeeba\SocialLogin\Library\Helper\Joomla;
use Joomla\CMS\Document\HtmlDocument;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;

defined('_JEXEC') or die();

if (!class_exists('Akeeba\\SocialLogin\\Library\\Plugin\\AbstractPlugin', true))
{
	return;
}

/**
 * Akeeba Social Login plugin for Twitter integration
 */
class plgSocialloginWebauthn extends CMSPlugin
{
	/**
	 * The integration slug used by this plugin.
	 *
	 * @var   string
	 */
	protected $integrationName = '';

	/**
	 * Should I output inline custom CSS in the page header to style this plugin's login, link and unlink buttons?
	 *
	 * @var   bool
	 */
	protected $useCustomCSS = true;

	/**
	 * The icon class to be used in the buttons.
	 *
	 * @var   string
	 */
	protected $iconClass = '';

	/**
	 * Relative media URL to the image used in buttons, e.g. 'plg_sociallogin_foobar/my_logo.png'.
	 *
	 * @var   string
	 */
	protected $buttonImage = '';

	/**
	 * Custom CSS for the login, link and unlink buttons of this social network.
	 *
	 * @var string
	 */
	protected $customCSS = '';

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

		// Load the language files
		$this->loadLanguage();

		// Set the integration name from the plugin name (without the plg_sociallogin_ part, of course)
		$this->integrationName = isset($config['sociallogin.integrationName']) ? $config['sociallogin.integrationName'] : $this->_name;

		// Register a debug log file writer
		Joomla::addLogger($this->integrationName);

		// Register the autoloader
		JLoader::registerNamespace('Akeeba\\SocialLogin\\Webauthn', __DIR__ . '/Webauthn', false, false, 'psr4');

		// Per-plugin customization
		$this->buttonImage = 'plg_sociallogin_webauthn/webauthn-color.png';
		$this->customCSS = /** @lang CSS */
			<<< CSS
.akeeba-sociallogin-link-button-webauthn, .akeeba-sociallogin-unlink-button-webauthn, .akeeba-sociallogin-button-webauthn { background-color: #ffffff
; color: #000000; transition-duration: 0.33s; background-image: none; border-color: #cccccc; }
.akeeba-sociallogin-link-button-webauthn:hover, .akeeba-sociallogin-unlink-button-webauthn:hover, .akeeba-sociallogin-button-webauthn:hover { background-color: #f0f0f0; color: #333333; transition-duration: 0.33s; border-color: #999999; }
.akeeba-sociallogin-link-button-webauthn img, .akeeba-sociallogin-unlink-button-webauthn img, .akeeba-sociallogin-button-webauthn img { display: inline-block; width: 22px; height: 16px; margin: 0 0.33em 0.1em 0; padding: 0 }

CSS;

		// Load the plugin options into properties
		$this->useCustomCSS        = $this->params->get('customcss', true);
		$this->iconClass           = $this->params->get('icon_class', '');
	}

	/**
	 * Adds custom CSS to the page's head unless we're explicitly told not to. The CSS helps render the buttons with the
	 * correct branding color.
	 *
	 * @return  void
	 *
	 * @throws  Exception
	 */
	protected function addCustomCSS()
	{
		// Make sure we only output the custom CSS once
		static $hasOutputCustomCSS = false;

		if ($hasOutputCustomCSS)
		{
			return;
		}

		$hasOutputCustomCSS = true;

		// Am I allowed to add my custom CSS?
		if (!$this->useCustomCSS)
		{
			return;
		}

		$jDocument = Joomla::getApplication()->getDocument();

		if (empty($jDocument) || !is_object($jDocument) || !($jDocument instanceof HtmlDocument))
		{
			return;
		}

		$jDocument->addStyleDeclaration($this->customCSS);
	}
}
