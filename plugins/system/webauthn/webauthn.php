<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

// Protect from unauthorized access
use Akeeba\Passwordless\Helper\Joomla;
use Akeeba\Passwordless\Webauthn\Exception\AjaxNonCmsAppException;
use Joomla\CMS\Document\HtmlDocument;
use Joomla\CMS\Form\Form;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\Utilities\ArrayHelper;

defined('_JEXEC') or die();

/**
 * Akeeba Passwordless Login plugin providing Webauthn integration
 */
class plgSystemWebauthn extends CMSPlugin
{
	/**
	 * Am I supposed to inject buttons?
	 *
	 * @var   bool
	 */
	private $enabled = true;

	/**
	 * The names of the login modules to intercept. Default: mod_login
	 *
	 * @var   array
	 */
	private $loginModules = array('mod_login');

	/**
	 * Should I intercept the login page of com_users and add passwordless login buttons there?
	 *
	 * @var   bool
	 */
	private $interceptLogin = true;

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
	 * Relative media URL to the image used in buttons, e.g. 'plg_system_foobar/my_logo.png'.
	 *
	 * @var   string
	 */
	protected $buttonImage = '';

	/**
	 * Custom CSS for the buttons.
	 *
	 * TODO Get rid of this. Use a regular CSS file instead.
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

		// Register a debug log file writer
		Joomla::addLogger('system');

		// Register the autoloader
		JLoader::registerNamespace('Akeeba\\Passwordless\\Webauthn', __DIR__ . '/Webauthn', false, false, 'psr4');

		// Per-plugin customization
		$this->buttonImage = 'plg_system_webauthn/webauthn-color.png';
		$this->customCSS   = /** @lang CSS */
			<<< CSS
.akeeba-passwordless-link-button-webauthn, .akeeba-passwordless-unlink-button-webauthn, .akeeba-passwordless-button-webauthn { background-color: #ffffff
; color: #000000; transition-duration: 0.33s; background-image: none; border-color: #cccccc; }
.akeeba-passwordless-link-button-webauthn:hover, .akeeba-passwordless-unlink-button-webauthn:hover, .akeeba-passwordless-button-webauthn:hover { background-color: #f0f0f0; color: #333333; transition-duration: 0.33s; border-color: #999999; }
.akeeba-passwordless-link-button-webauthn img, .akeeba-passwordless-unlink-button-webauthn img, .akeeba-passwordless-button-webauthn img { display: inline-block; width: 22px; height: 16px; margin: 0 0.33em 0.1em 0; padding: 0 }

CSS;

		// Am I enabled?
		$this->enabled = $this->isEnabled();

		if ($this->enabled)
		{
			// Get the configured list of login modules and convert it to an actual array
			$isAdminPage           = Joomla::isAdminPage();
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
	}

	/**
	 * We need to log into the backend BUT com_ajax is not accessible unless we are already logged in. Moreover, since
	 * the backend is a separate application from the frontend we cannot share the user session between them. Therefore
	 * I am going to write my own AJAX handler for the backend by abusing the onAfterInitialize event.
	 *
	 * @return  void
	 *
	 * @throws  Exception
	 */
	public function onAfterInitialise()
	{
		// Make sure this is the backend of the site...
		if (!Joomla::isAdminPage())
		{
			return;
		}

		// ...and we are not already logged in...
		if (!Joomla::getUser()->guest)
		{
			return;
		}

		$app   = Joomla::getApplication();
		$input = $app->input;

		// ...and this is a request to com_ajax...
		if ($input->getCmd('option', '') != 'com_ajax')
		{
			return;
		}

		// ...about a system plugin...
		if ($input->getCmd('group', '') != 'system')
		{
			return;
		}

		// ...called 'webauthn'
		if ($input->getCmd('plugin', '') != 'webauthn')
		{
			return;
		}

		/**
		 * Why do we go through onAjaxWebauthn instead of importing the code directly in here?
		 *
		 * AJAX responses are called through com_ajax. In the frontend the com_ajax component itself is handling the
		 * request, without going through our special onAfterInitialize handler. As a result, it calls the
		 * onAjaxWebauthn plugin event directly.
		 *
		 * In the backend, however, com_ajax is not accessible before we log in. This doesn't help us any since we need
		 * it when we are not logged in, to perform the passwordless login. Therefore our special onAfterInitialize
		 * code kicks in and simulates what com_ajax would do, to a degree that it's sufficient for our purposes.
		 *
		 * Only in the second case would it make sense to import the code here. In the interest of keeping it DRY we do
		 * not do that, instead going through the plugin event with a negligible performance impact in the order of a
		 * millisecond or less. This is orders of magnitude less than the roundtrip time of the AJAX request.
		 */
		Joomla::runPlugins('onAjaxWebauthn', []);
	}

	/**
	 * Processes the callbacks from the passwordless login views.
	 *
	 * Note: this method is called from Joomla's com_ajax or, in the case of backend logins, through the special
	 * onAfterInitialize handler we have created to work around com_ajax usage limitations in the backend.
	 *
	 * @return  void
	 *
	 * @throws  Exception
	 */
	public function onAjaxWebauthn()
	{
		$app   = Joomla::getApplication();
		$input = $app->input;

		// Get the return URL from the session
		$returnURL = Joomla::getSessionVar('returnUrl', JUri::base(), 'plg_system_webauthn');
		Joomla::setSessionVar('returnUrl', null, 'plg_system_webauthn');
		$result = null;

		try
		{
			Joomla::log('system', "Received AJAX callback.");

			if (!Joomla::isCmsApplication($app))
			{
				throw new AjaxNonCmsAppException();
			}

			$input    = $app->input;
			$akaction = $input->getCmd('akaction');
			$token    = Joomla::getToken();

			if ($input->getInt($token, 0) != 1)
			{
				throw new RuntimeException(Joomla::_('JERROR_ALERTNOAUTHOR'));
			}

			// Empty action? No bueno.
			if (empty($akaction))
			{
				throw new RuntimeException(Joomla::_('PLG_SYSTEM_WEBAUTHN_ERR_AJAX_INVALIDACTION'));
			}

			// Call the plugin event onAjaxWebauthnSomething where Something is the akaction param.
			$eventName = 'onAjaxWebauthn' . ucfirst($akaction);

			$results = Joomla::runPlugins($eventName, [], $app);
			$result = null;

			foreach ($results as $r)
			{
				if (is_null($r))
				{
					continue;
				}

				$result = $r;

				break;
			}
		}
		catch (AjaxNonCmsAppException $e)
		{
			Joomla::log('system', "This is not a CMS application", Log::NOTICE);

			$result = null;
		}
		catch (Exception $e)
		{
			Joomla::log('system', "Callback failure, redirecting to $returnURL.");
			$app->enqueueMessage($e->getMessage(), 'error');
			$app->redirect($returnURL);

			return;
		}

		if ($result != null)
		{
			switch ($input->getCmd('encoding', 'json'))
			{
				default:
				case 'json':
					Joomla::log('system', "Callback complete, returning JSON.");
					echo json_encode($result);

					break;

				case 'jsonhash':
					Joomla::log('system', "Callback complete, returning JSON inside ### markers.");
					echo '###' . json_encode($result) . '###';

					break;

				case 'raw':
					Joomla::log('system', "Callback complete, returning raw response.");
					echo $result;

					break;

				case 'redirect':
					$modifiers = '';

					if (isset($result['message']))
					{
						$type = isset($result['type']) ? $result['type'] : 'info';
						$app->enqueueMessage($result['message'], $type);

						$modifiers = " and setting a system message of type $type";
					}

					if (isset($result['url']))
					{
						Joomla::log('system', "Callback complete, performing redirection to {$result['url']}{$modifiers}.");
						$app->redirect($result['url']);
					}


					Joomla::log('system', "Callback complete, performing redirection to {$result}{$modifiers}.");
					$app->redirect($result);

					return;
					break;
			}

			$app->close(200);
		}

		Joomla::log('system', "Null response from AJAX callback, redirecting to $returnURL");

		$app->redirect($returnURL);
	}


	/**
	 * Intercepts module rendering, appending the Webauthn button to the configured login module.
	 *
	 * @param   object  $module   The module being rendered
	 * @param   object  $attribs  The module rendering attributes
	 *
	 * @throws  Exception
	 */
	public function onRenderModule(&$module, &$attribs)
	{
		if (!$this->enabled)
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
				$this->enabled = false;

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
		// TODO Get the content we need to append to the module
		$passwordlessContent = '';
		$module->content    .= $passwordlessContent;
	}


	/**
	 * Should I enable the substitutions performed by this plugin?
	 *
	 * @return  bool
	 */
	private function isEnabled()
	{
		// It only make sense to let people log in when they are not already logged in ;)
		if (!Joomla::getUser()->guest)
		{
			return false;
		}

		return true;
	}

	/**
	 * Adds additional fields to the user editing form
	 *
	 * @param   JForm  $form  The form to be altered.
	 * @param   mixed  $data  The associated data for the form.
	 *
	 * @return  boolean
	 *
	 * @throws  Exception
	 */
	public function onContentPrepareForm($form, $data)
	{
		// Check we are manipulating a valid form.
		if (!($form instanceof Form))
		{
			return true;
		}

		$name = $form->getName();

		if (!in_array($name, array('com_admin.profile', 'com_users.user', 'com_users.profile', 'com_users.registration')))
		{
			return true;
		}

		if (!Joomla::isAdminPage() && (Joomla::getApplication()->input->getCmd('layout', 'default') != 'edit'))
		{
			return true;
		}

		// Get the user ID
		$id = null;

		if (is_array($data))
		{
			$id = isset($data['id']) ? $data['id'] : null;
		}
		elseif (is_object($data) && is_null($data) && ($data instanceof JRegistry))
		{
			$id = $data->get('id');
		}
		elseif (is_object($data) && !is_null($data))
		{
			$id = isset($data->id) ? $data->id : null;
		}

		$user = Joomla::getUser($id);

		// Make sure the loaded user is the correct one
		if ($user->id != $id)
		{
			return true;
		}

		// Make sure I am either editing myself OR I am a Super User
		if (!Joomla::canEditUser($user))
		{
			return true;
		}

		// Add the fields to the form.
		Joomla::log('system', 'Injecting Akeeba Passwordless Login fields in user profile edit page');
		$this->loadLanguage();
		Form::addFormPath(dirname(__FILE__) . '/fields');
		$form->loadFile('webauthn', false);

		return true;
	}

	/**
	 * Remove all passwordless credential information for the given user ID
	 *
	 * Method is called after user data is deleted from the database
	 *
	 * @param   array   $user     Holds the user data
	 * @param   bool    $success  True if user was successfully stored in the database
	 * @param   string  $msg      Message
	 *
	 * @return  bool
	 *
	 * @throws  Exception
	 */
	public function onUserAfterDelete($user, $success, $msg)
	{
		if (!$success)
		{
			return false;
		}

		$userId = ArrayHelper::getValue($user, 'id', 0, 'int');

		if ($userId)
		{
			Joomla::log('system', "Removing Akeeba Passwordless Login information for deleted user #{$userId}");

			$db = Joomla::getDbo();

			$query = $db->getQuery(true)
				->delete($db->qn('#__webauthn_credentials'))
				->where($db->qn('user_id').' = '.$db->q($userId));

			$db->setQuery($query)->execute();
		}

		return true;
	}

	/**
	 * Adds custom CSS to the page's head unless we're explicitly told not to. The CSS helps render the buttons with the
	 * correct branding color.
	 *
	 * TODO Get rid of this, use a regular CSS file instead.
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
