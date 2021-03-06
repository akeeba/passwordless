<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2021 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Passwordless\PluginTraits;

// Protect from unauthorized access
defined('_JEXEC') or die();

use Akeeba\Passwordless\Helper\Integration;
use Akeeba\Passwordless\Helper\Joomla;
use Exception;

/**
 * Inserts Webauthn buttons into the login page rendered by Joomla's com_user
 */
trait ButtonsInUserPage
{
	/**
	 * Should I intercept the login page of com_users and add passwordless login buttons there? User configurable.
	 *
	 * @var   bool
	 */
	protected $interceptLogin = true;

	/**
	 * Called after a component has finished running, right after Joomla has set the component output to the buffer.
	 * Used to inject our login button in the front-end login page rendered by com_users.
	 *
	 * @return  void
	 */
	public function onAfterDispatch(): void
	{
		// Are we enabled?
		if (!$this->interceptLogin || $this->useJ4Injection())
		{
			return;
		}

		// Make sure I can get basic information
		try
		{
			$app     = Joomla::getApplication();
			$user    = Joomla::getUser();
			$isAdmin = Joomla::isAdminPage($app);
			$input   = $app->input;
		}
		catch (Exception $e)
		{
			return;
		}

		// No point showing a login button when you're already logged in
		if (!$user->guest)
		{
			return;
		}

		// I can only operate in frontend pages
		if ($isAdmin)
		{
			return;
		}

		// Make sure this is the Users component
		$option = $input->getCmd('option');

		if ($option !== 'com_users')
		{
			return;
		}

		// Make sure it is the right view / task
		$fallbackView = version_compare(JVERSION, '3.999.999', 'ge')
			? $view = $input->getCmd('controller', '')
			: '';
		$view         = $input->getCmd('view', $fallbackView);
		$task         = $input->getCmd('task');

		if (strpos($task, '.') !== false)
		{
			$parts = explode('.', $task);
			$view = ($parts[0] ?? $view) ?: $view;
			$task = ($parts[1] ?? $task) ?: $task;
		}

		$check1 = is_null($view) && is_null($task);
		$check2 = is_null($view) && ($task === 'login');
		$check3 = ($view === 'login') && is_null($task);

		if (!$check1 && !$check2 && !$check3)
		{
			return;
		}

		// Make sure it's an HTML document
		$document = $app->getDocument();

		if ($document->getType() != 'html')
		{
			return;
		}

		// Get the component output and append our buttons
		$buttons = Integration::getLoginButtonHTML([
			'relocate' => true,
		]);

		$buffer          = $document->getBuffer();
		$componentOutput = $buffer['component'][''][''];
		$componentOutput .= $buttons;
		$document->setBuffer($componentOutput, 'component');
	}

	/**
	 * Set up the login page button injection feature.
	 *
	 * @return  void
	 */
	protected function setupUserLoginPageButtons(): void
	{
		// Don't try to set up this feature if we are alraedy logged in
		if (!$this->isButtonInjectionNecessary())
		{
			return;
		}

		$this->interceptLogin = $this->params->get('interceptlogin', 1);
	}
}