<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Joomla\Plugin\System\Passwordless\Extension\Traits;

// Protect from unauthorized access
defined('_JEXEC') or die();

use Exception;
use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Event\GenericEvent;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Uri\Uri;
use Joomla\Plugin\System\Passwordless\Exception\AjaxNonCmsAppException;
use RuntimeException;

/**
 * Allows the plugin to handle AJAX requests in the backend of the site, where com_ajax is not available when we are not
 * logged in.
 *
 * @since 1.0.0
 */
trait AjaxHandler
{
	/**
	 * We need to log into the backend BUT com_ajax is not accessible unless we are already logged in. Moreover, since
	 * the backend is a separate application from the frontend we cannot share the user session between them. Therefore
	 * I am going to write my own AJAX handler for the backend by abusing the onAfterInitialize event.
	 *
	 * @return  void
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	private function onAfterInitialiseAjax(): void
	{
		// Only applies when it's the administrator application with no user logged in
		$user = $this->app->getIdentity();

		if (!$this->app->isClient('administrator') || empty($user) || !$user->guest)
		{
			return;
		}

		$input = $this->app->input;

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

		// ...called 'passwordless'
		if ($input->getCmd('plugin', '') != 'passwordless')
		{
			return;
		}

		/**
		 * Why do we go through onAjaxPasswordless instead of importing the code directly in here?
		 *
		 * AJAX responses are called through com_ajax. In the frontend the com_ajax component itself is handling the
		 * request, without going through our special onAfterInitialize handler. As a result, it calls the
		 * onAjaxPasswordless plugin event directly.
		 *
		 * In the backend, however, com_ajax is not accessible before we log in. This doesn't help us any since we need
		 * it when we are not logged in, to perform the passwordless login. Therefore our special onAfterInitialize
		 * code kicks in and simulates what com_ajax would do, to a degree that it's sufficient for our purposes.
		 *
		 * Only in the second case would it make sense to import the code here. In the interest of keeping it DRY we do
		 * not do that, instead going through the plugin event with a negligible performance impact in the order of a
		 * millisecond or less. This is orders of magnitude less than the roundtrip time of the AJAX request.
		 */
		$event = new GenericEvent('onAjaxPasswordless', []);
		$this->app->getDispatcher()->dispatch($event->getName(), $event);
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
	 * @since   1.0.0
	 */
	public function onAjaxPasswordless(): void
	{
		try
		{
			Log::add(Log::INFO, 'plg_system_passwordless', 'Received AJAX callback.');

			if (!($this->app instanceof CMSApplication))
			{
				throw new AjaxNonCmsAppException();
			}

			$input = $this->app->input;

			// Get the return URL from the session
			$returnURL = $this->app->getSession()->get('plg_system_passwordless.returnUrl', Uri::base());
			$result    = null;

			$input    = $this->app->input;
			$akaction = $input->getCmd('akaction');
			$token    = $this->app->getFormToken();

			if ($input->getInt($token, 0) != 1)
			{
				throw new RuntimeException(Text::_('JERROR_ALERTNOAUTHOR'));
			}

			// Empty action? No bueno.
			if (empty($akaction))
			{
				throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_AJAX_INVALIDACTION'));
			}

			// Call the plugin event onAjaxPasswordlessSomething where Something is the akaction param.
			$eventName = 'onAjaxPasswordless' . ucfirst($akaction);
			$event     = new GenericEvent($eventName, []);
			$result    = $this->app->getDispatcher()->dispatch($eventName, $event);
			$results   = !isset($result['result']) || \is_null($result['result']) ? [] : $result['result'];
			$result    = null;

			$result = array_reduce($results, function ($carry, $result) {
				return $carry ?? $result;
			}, null);
		}
		catch (AjaxNonCmsAppException $e)
		{
			Log::add(Log::NOTICE, 'plg_system_passwordless', 'This is not a CMS application');

			$result = null;
		}
		catch (Exception $e)
		{
			Log::add(Log::INFO, 'plg_system_passwordless', sprintf('Callback failure, redirecting to %s.', $returnURL));

			$this->app->getSession()->set('plg_system_passwordless.returnUrl', null);
			$this->app->enqueueMessage($e->getMessage(), 'error');
			$this->app->redirect($returnURL);

			return;
		}

		if (!is_null($result))
		{
			switch ($input->getCmd('encoding', 'json'))
			{
				default:
				case 'json':
					Log::add(Log::INFO, 'plg_system_passwordless', 'Callback complete, returning JSON.');
					echo json_encode($result);

					break;

				case 'jsonhash':
					Log::add(Log::INFO, 'plg_system_passwordless', 'Callback complete, returning JSON inside ### markers.');
					echo '###' . json_encode($result) . '###';

					break;

				case 'raw':
					Log::add(Log::INFO, 'plg_system_passwordless', 'Callback complete, returning raw response.');
					echo $result;

					break;

				case 'redirect':
					$modifiers = '';

					if (isset($result['message']))
					{
						$type = $result['type'] ?? 'info';
						$this->app->enqueueMessage($result['message'], $type);

						$modifiers = " and setting a system message of type $type";
					}

					if (isset($result['url']))
					{
						Log::add(Log::INFO, 'plg_system_passwordless', sprintf('Callback complete, performing redirection to %s%s.', $result['url'], $modifiers));
						$this->app->redirect($result['url']);
					}


					Log::add(Log::INFO, 'plg_system_passwordless', sprintf('Callback complete, performing redirection to %s%s.', $result, $modifiers));
					$this->app->redirect($result);

					return;
					break;
			}

			$this->app->close(200);
		}

		Log::add(Log::INFO, 'plg_system_passwordless', sprintf('Null response from AJAX callback, redirecting to %s', $returnURL));

		$this->app->getSession()->set('plg_system_passwordless.returnUrl', null);
		$this->app->redirect($returnURL);
	}
}