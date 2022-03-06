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
use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Authentication\AuthenticationResponse;
use Joomla\CMS\Event\GenericEvent;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\Plugin\System\Passwordless\Credential\Authentication as CredentialsAuthentication;
use Joomla\Plugin\System\Passwordless\Credential\CredentialsRepository;
use RuntimeException;

/**
 * Ajax handler for akaction=login
 *
 * Verifies the response received from the browser and logs in the user
 */
trait AjaxHandlerLogin
{
	/**
	 * Returns the public key set for the user and a unique challenge in a Public Key Credential Request encoded as
	 * JSON.
	 *
	 * @return  string  A JSON-encoded object or JSON-encoded false if the username is invalid or no credentials stored
	 *
	 * @throws  Exception
	 *
	 * @since   1.0.0
	 */
	public function onAjaxPasswordlessLogin(): void
	{
		$returnUrl = $this->app->getSession()->get('plg_system_passwordless.returnUrl', Uri::base());
		$userId    = $this->app->getSession()->get('plg_system_passwordless.userId', 0);

		try
		{
			// Validate the authenticator response and get the user handle
			$userHandle           = $this->getUserHandleFromResponse();
			$credentialRepository = new CredentialsRepository();

			if (is_null($userHandle))
			{
				throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
			}

			// If a user ID is NOT present in the session we need to get it from the user handle
			if (empty($userId))
			{
				$userId = $credentialRepository->getUserIdFromHandle($userHandle);
			}

			// No user ID: no username was provided and the resident credential refers to an unknown user handle. DIE!
			if (empty($userId))
			{
				throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
			}

			// Does the user handle match the user ID? This should never trigger by definition of the login check.
			if ($userHandle != $credentialRepository->getHandleFromUserId($userId))
			{
				throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
			}

			// Make sure the user exists
			$user = Factory::getContainer()->get(UserFactoryInterface::class)->loadUserById($userId);

			if ($user->id != $userId)
			{
				throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
			}

			// Login the user
			Log::add(Log::INFO, 'plg_system_passwordless', 'Logging in the user');
			$this->loginUser((int) $userId);
		}
		catch (\Throwable $e)
		{
			$this->app->getSession()->set('plg_system_passwordless.publicKeyCredentialRequestOptions', null);
			$this->app->getSession()->set('plg_system_passwordless.userHandle', null);

			$response                = $this->getAuthenticationResponseObject();
			$response->status        = Authentication::STATUS_UNKNOWN;
			$response->error_message = $e->getMessage();

			Log::add(Log::ERROR, 'plg_system_passwordless', sprintf('Received login failure. Message: %s', $e->getMessage()));

			// This also enqueues the login failure message for display after redirection. Look for JLog in that method.
			$this->processLoginFailure($response);
		}
		finally
		{
			/**
			 * This code needs to run no matter if the login succeeded or failed. It prevents replay attacks and takes
			 * the user back to the page they started from.
			 */

			// Remove temporary information for security reasons
			$this->app->getSession()->set('plg_system_passwordless.publicKeyCredentialRequestOptions', null);
			$this->app->getSession()->set('plg_system_passwordless.userHandle', null);
			$this->app->getSession()->set('plg_system_passwordless.returnUrl', null);
			$this->app->getSession()->set('plg_system_passwordless.userId', null);

			// Redirect back to the page we were before.
			$this->app->redirect($returnUrl);
		}
	}

	/**
	 * Logs in a user to the site, bypassing the authentication plugins.
	 *
	 * @param   int  $userId  The user ID to log in
	 *
	 * @throws Exception
	 * @since   1.0.0
	 */
	private function loginUser(int $userId): void
	{
		// Trick the class auto-loader into loading the necessary classes
		class_exists('Joomla\\CMS\\Authentication\\Authentication', true);

		// Fake a successful login message
		$isAdmin = $this->app->isClient('administrator');
		$user    = Factory::getContainer()->get(UserFactoryInterface::class)->loadUserById($userId);

		// Does the user account have a pending activation?
		if (!empty($user->activation))
		{
			throw new RuntimeException(Text::_('JGLOBAL_AUTH_ACCESS_DENIED'));
		}

		// Is the user account blocked?
		if ($user->block)
		{
			throw new RuntimeException(Text::_('JGLOBAL_AUTH_ACCESS_DENIED'));
		}

		$statusSuccess = Authentication::STATUS_SUCCESS;

		$response                = $this->getAuthenticationResponseObject();
		$response->status        = $statusSuccess;
		$response->username      = $user->username;
		$response->fullname      = $user->name;
		$response->error_message = '';
		$response->language      = $user->getParam('language');
		$response->type          = 'Passwordless';

		if ($isAdmin)
		{
			$response->language = $user->getParam('admin_language');
		}

		/**
		 * Set up the login options.
		 *
		 * The 'remember' element forces the use of the Remember Me feature when logging in with Webauthn, as the
		 * users would expect.
		 *
		 * The 'action' element is actually required by plg_user_joomla. It is the core ACL action the logged in user
		 * must be allowed for the login to succeed. Please note that front-end and back-end logins use a different
		 * action. This allows us to provide the social login button on both front- and back-end and be sure that if a
		 * used with no backend access tries to use it to log in Joomla! will just slap him with an error message about
		 * insufficient privileges - the same thing that'd happen if you tried to use your front-end only username and
		 * password in a back-end login form.
		 */
		$options = [
			'remember' => true,
			'action'   => 'core.login.site',
		];

		if ($isAdmin)
		{
			$options['action'] = 'core.login.admin';
		}

		// Run the user plugins. They CAN block login by returning boolean false and setting $response->error_message.
		PluginHelper::importPlugin('user');
		$event   = new GenericEvent('onUserLogin', [(array) $response, $options]);
		$result  = $this->app->getDispatcher()->dispatch($event->getName(), $event);
		$results = !isset($result['result']) || \is_null($result['result']) ? [] : $result['result'];

		// If there is no boolean FALSE result from any plugin the login is successful.
		if (in_array(false, $results, true) === false)
		{
			// Set the user in the session, letting Joomla! know that we are logged in.
			$this->app->getSession()->set('user', $user);

			// Trigger the onUserAfterLogin event
			$options['user']         = $user;
			$options['responseType'] = $response->type;

			// The user is successfully logged in. Run the after login events
			$event = new GenericEvent('onUserAfterLogin', [$options]);
			$this->app->getDispatcher()->dispatch($event->getName(), $event);

			return;
		}

		// If we are here the plugins marked a login failure. Trigger the onUserLoginFailure Event.
		$event = new GenericEvent('onUserLoginFailure', [(array) $response]);
		$this->app->getDispatcher()->dispatch($event->getName(), $event);

		// Log the failure
		Log::add($response->error_message, Log::WARNING, 'jerror');

		// Throw an exception to let the caller know that the login failed
		throw new RuntimeException($response->error_message);
	}

	/**
	 * Returns a (blank) Joomla! authentication response
	 *
	 * @return  AuthenticationResponse
	 *
	 * @since   1.0.0
	 */
	private function getAuthenticationResponseObject(): AuthenticationResponse
	{
		// Force the class auto-loader to load the JAuthentication class
		class_exists('Joomla\\CMS\\Authentication\\Authentication', true);

		return new AuthenticationResponse();
	}

	/**
	 * Have Joomla! process a login failure
	 *
	 * @param   AuthenticationResponse  $response  The Joomla! auth response object
	 *
	 * @return  bool
	 *
	 * @since   1.0.0
	 */
	private function processLoginFailure(AuthenticationResponse $response)
	{
		// Import the user plugin group.
		PluginHelper::importPlugin('user');

		// Trigger onUserLoginFailure Event.
		Log::add(Log::INFO, 'plg_system_passwordless', "Calling onUserLoginFailure plugin event");

		$event = new GenericEvent('onUserLoginFailure', [(array) $response]);
		$this->app->getDispatcher()->dispatch($event->getName(), $event);

		// If status is success, any error will have been raised by the user plugin
		$expectedStatus = Authentication::STATUS_SUCCESS;

		if ($response->status !== $expectedStatus)
		{
			Log::add(Log::INFO, 'plg_system_passwordless', 'The login failure has been logged in Joomla\'s error log');

			// Everything logged in the 'jerror' category ends up being enqueued in the application message queue.
			Log::add($response->error_message, Log::WARNING, 'jerror');
		}
		else
		{
			Log::add(Log::WARNING, 'plg_system_passwordless', 'The login failure was caused by a third party user plugin but it did not return any further information. Good luck figuring this one out...');
		}

		return false;
	}

	/**
	 * Validate the authenticator response sent to us by the browser.
	 *
	 * @return  string|null  The user handle or null
	 *
	 * @throws  Exception
	 *
	 * @since   1.0.0
	 */
	private function getUserHandleFromResponse(): ?string
	{
		// Retrieve data from the request and session
		$pubKeyCredentialSource = CredentialsAuthentication::validateAssertionResponse(
			$this->app->input->getBase64('data', '')
		);

		return $pubKeyCredentialSource ? $pubKeyCredentialSource->getUserHandle() : null;
	}
}