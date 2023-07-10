<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Plugin\System\Passwordless\PluginTraits;

defined('_JEXEC') or die();

use Exception;
use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Event\GenericEvent;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Uri\Uri;
use Joomla\Event\Event;
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
	public function onAjaxPasswordless(Event $event)
	{
		$input = $this->getApplication()->input;

		// Get the return URL from the session
		$returnURL = $this->getApplication()->getSession()->get('plg_system_webauthn.returnUrl', Uri::base());
		$result    = null;

		try
		{
			Log::add('Received AJAX callback.', Log::DEBUG, 'plg_system_passwordless');

			if (!($this->getApplication() instanceof CMSApplication))
			{
				Log::add("This is not a CMS application", Log::NOTICE, 'plg_system_passwordless');

				return;
			}

			$akaction = $input->getCmd('akaction');

			if (!$this->getApplication()->checkToken('request'))
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
			$result    = $this->getApplication()->getDispatcher()->dispatch($eventName, $event);
			$results   = !isset($result['result']) || \is_null($result['result']) ? [] : $result['result'];
			$result    = null;
			$reducer   = function ($carry, $result)
			{
				return $carry ?? $result;
			};
			$result    = array_reduce($results, $reducer, null);
		}
		catch (Exception $e)
		{
			Log::add(sprintf('Callback failure, redirecting to %s.', $returnURL), Log::DEBUG, 'plg_system_passwordless');

			$this->getApplication()->getSession()->set('plg_system_passwordless.returnUrl', null);
			$this->getApplication()->enqueueMessage($e->getMessage(), 'error');
			$this->getApplication()->redirect($returnURL);

			return;
		}

		if (!is_null($result))
		{
			switch ($input->getCmd('encoding', 'json'))
			{
				case 'raw':
					Log::add('Callback complete, returning raw response.', Log::DEBUG, 'plg_system_passwordless');
					echo $result;

					break;

				case 'redirect':
					$modifiers = '';

					if (isset($result['message']))
					{
						$type = $result['type'] ?? 'info';
						$this->getApplication()->enqueueMessage($result['message'], $type);

						$modifiers = " and setting a system message of type $type";
					}

					if (isset($result['url']))
					{
						Log::add(sprintf('Callback complete, performing redirection to %s%s.', $result['url'], $modifiers), Log::DEBUG, 'plg_system_passwordless');
						$this->getApplication()->redirect($result['url']);
					}


					Log::add(sprintf('Callback complete, performing redirection to %s%s.', $result, $modifiers), Log::DEBUG, 'plg_system_passwordless');
					$this->getApplication()->redirect($result);

					return;

				default:
				case 'json':
					Log::add('Callback complete, returning JSON.', Log::DEBUG, 'plg_system_passwordless');
					echo json_encode($result);

					break;
			}

			$this->getApplication()->close(200);
		}

		Log::add(sprintf('Null response from AJAX callback, redirecting to %s', $returnURL). Log::DEBUG, 'plg_system_passwordless');

		$this->getApplication()->getSession()->set('plg_system_passwordless.returnUrl', null);
		$this->getApplication()->redirect($returnURL);
	}
}