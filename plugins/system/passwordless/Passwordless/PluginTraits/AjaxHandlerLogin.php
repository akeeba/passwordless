<?php
/*
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2020 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Passwordless\PluginTraits;

// Protect from unauthorized access
defined('_JEXEC') or die();

use Akeeba\Passwordless\CredentialRepository;
use Akeeba\Passwordless\Helper\Joomla;
use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA;
use Cose\Algorithm\Signature\EdDSA;
use Cose\Algorithm\Signature\RSA;
use Exception;
use JLoader;
use Joomla\CMS\Application\BaseApplication;
use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Authentication\AuthenticationResponse;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\CMS\Uri\Uri;
use RuntimeException;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;
use Zend\Diactoros\ServerRequestFactory;

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
		$returnUrl = Joomla::getSessionVar('returnUrl', Uri::base(), 'plg_system_passwordless');
		$userId    = Joomla::getSessionVar('userId', 0, 'plg_system_passwordless');

		try
		{
			// Validate the authenticator response and get the user handle
			$userHandle           = $this->getUserHandleFromResponse();
			$credentialRepository = new CredentialRepository();

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
			$user = Joomla::getUser($userId);

			if ($user->id != $userId)
			{
				throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
			}

			// Login the user
			Joomla::log('system', "Logging in the user", Log::INFO);
			$this->loginUser((int) $userId);
		}
		catch (\Throwable $e)
		{
			Joomla::setSessionVar('publicKeyCredentialRequestOptions', null, 'plg_system_passwordless');
			Joomla::setSessionVar('userHandle', null, 'plg_system_passwordless');

			$response                = $this->getAuthenticationResponseObject();
			$response->status        = Authentication::STATUS_UNKNOWN;
			$response->error_message = $e->getMessage();

			Joomla::log('system', sprintf("Received login failure. Message: %s", $e->getMessage()), Log::ERROR);

			// This also enqueues the login failure message for display after redirection. Look for JLog in that method.
			$this->processLoginFailure($response, null, 'system');
		}
		finally
		{
			/**
			 * This code needs to run no matter if the login succeeded or failed. It prevents replay attacks and takes
			 * the user back to the page they started from.
			 */

			// Remove temporary information for security reasons
			Joomla::setSessionVar('publicKeyCredentialRequestOptions', null, 'plg_system_passwordless');
			Joomla::setSessionVar('userHandle', null, 'plg_system_passwordless');
			Joomla::setSessionVar('returnUrl', null, 'plg_system_passwordless');
			Joomla::setSessionVar('userId', null, 'plg_system_passwordless');

			// Redirect back to the page we were before.
			Joomla::getApplication()->redirect($returnUrl);
		}
	}

	/**
	 * Logs in a user to the site, bypassing the authentication plugins.
	 *
	 * @param   int              $userId  The user ID to log in
	 * @param   BaseApplication  $app     The application we are running in. Skip to auto-detect (recommended).
	 *
	 * @throws  Exception
	 *
	 * @since   1.0.0
	 */
	private function loginUser(int $userId, BaseApplication $app = null): void
	{
		// Trick the class auto-loader into loading the necessary classes
		JLoader::import('joomla.user.authentication');
		JLoader::import('joomla.plugin.helper');
		JLoader::import('joomla.user.helper');
		class_exists('Joomla\\CMS\\Authentication\\Authentication', true);

		// Fake a successful login message
		if (!is_object($app))
		{
			$app = Joomla::getApplication();
		}

		$isAdmin = $app->isClient('administrator');
		$user    = Joomla::getUser($userId);

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

		if (Joomla::isAdminPage())
		{
			$options['action'] = 'core.login.admin';
		}

		// Run the user plugins. They CAN block login by returning boolean false and setting $response->error_message.
		PluginHelper::importPlugin('user');
		$results = Joomla::runPlugins('onUserLogin', [(array) $response, $options], $app);

		// If there is no boolean FALSE result from any plugin the login is successful.
		if (in_array(false, $results, true) == false)
		{
			// Set the user in the session, letting Joomla! know that we are logged in.
			Joomla::setSessionVar('user', $user);

			// Trigger the onUserAfterLogin event
			$options['user']         = $user;
			$options['responseType'] = $response->type;

			// The user is successfully logged in. Run the after login events
			Joomla::runPlugins('onUserAfterLogin', [$options], $app);

			return;
		}

		// If we are here the plugins marked a login failure. Trigger the onUserLoginFailure Event.
		Joomla::runPlugins('onUserLoginFailure', [(array) $response], $app);

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
		JLoader::import('joomla.user.authentication');
		class_exists('Joomla\\CMS\\Authentication\\Authentication', true);

		return new AuthenticationResponse();
	}

	/**
	 * Have Joomla! process a login failure
	 *
	 * @param   AuthenticationResponse  $response    The Joomla! auth response object
	 * @param   BaseApplication         $app         The application we are running in. Skip to auto-detect
	 *                                               (recommended).
	 * @param   string                  $logContext  Logging context (plugin name). Default: system.
	 *
	 * @return  bool
	 *
	 * @throws  Exception
	 *
	 * @since   1.0.0
	 */
	private function processLoginFailure(AuthenticationResponse $response, BaseApplication $app = null, string $logContext = 'system')
	{
		// Import the user plugin group.
		PluginHelper::importPlugin('user');

		if (!is_object($app))
		{
			$app = Joomla::getApplication();
		}

		// Trigger onUserLoginFailure Event.
		Joomla::log($logContext, "Calling onUserLoginFailure plugin event");
		Joomla::runPlugins('onUserLoginFailure', [(array) $response], $app);

		// If status is success, any error will have been raised by the user plugin
		$expectedStatus = Authentication::STATUS_SUCCESS;

		if ($response->status !== $expectedStatus)
		{
			Joomla::log($logContext, "The login failure has been logged in Joomla's error log");

			// Everything logged in the 'jerror' category ends up being enqueued in the application message queue.
			Log::add($response->error_message, Log::WARNING, 'jerror');
		}
		else
		{
			Joomla::log($logContext, "The login failure was caused by a third party user plugin but it did not return any further information. Good luck figuring this one out...", Log::WARNING);
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
		// Initialize objects
		$input                = Joomla::getApplication()->input;
		$credentialRepository = new CredentialRepository();

		// Retrieve data from the request and session
		$data = $input->getBase64('data', '');
		$data = base64_decode($data);

		if (empty($data))
		{
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
		}

		$publicKeyCredentialRequestOptions = $this->getPKCredentialRequestOptions();

		// Cose Algorithm Manager
		$coseAlgorithmManager = new Manager();
		$coseAlgorithmManager->add(new ECDSA\ES256());
		$coseAlgorithmManager->add(new ECDSA\ES512());
		$coseAlgorithmManager->add(new EdDSA\EdDSA());
		$coseAlgorithmManager->add(new RSA\RS1());
		$coseAlgorithmManager->add(new RSA\RS256());
		$coseAlgorithmManager->add(new RSA\RS512());

		// Create a CBOR Decoder object
		$otherObjectManager = new OtherObjectManager();
		$tagObjectManager   = new TagObjectManager();
		$decoder            = new Decoder($tagObjectManager, $otherObjectManager);

		// Attestation Statement Support Manager
		$attestationStatementSupportManager = new AttestationStatementSupportManager();
		$attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
		$attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport($decoder));
		//$attestationStatementSupportManager->add(new AndroidSafetyNetAttestationStatementSupport(HttpFactory::getHttp(), 'GOOGLE_SAFETYNET_API_KEY', new RequestFactory()));
		$attestationStatementSupportManager->add(new AndroidKeyAttestationStatementSupport($decoder));
		$attestationStatementSupportManager->add(new TPMAttestationStatementSupport());
		$attestationStatementSupportManager->add(new PackedAttestationStatementSupport($decoder, $coseAlgorithmManager));

		// Attestation Object Loader
		$attestationObjectLoader = new AttestationObjectLoader($attestationStatementSupportManager, $decoder);

		// Public Key Credential Loader
		$publicKeyCredentialLoader = new PublicKeyCredentialLoader($attestationObjectLoader, $decoder);

		// The token binding handler
		$tokenBindingHandler = new TokenBindingNotSupportedHandler();

		// Extension Output Checker Handler
		$extensionOutputCheckerHandler = new ExtensionOutputCheckerHandler();

		// Authenticator Assertion Response Validator
		$authenticatorAssertionResponseValidator = new AuthenticatorAssertionResponseValidator(
			$credentialRepository,
			$decoder,
			$tokenBindingHandler,
			$extensionOutputCheckerHandler,
			$coseAlgorithmManager
		);

		// We init the Symfony Request object
		$request = ServerRequestFactory::fromGlobals();

		// Load the data
		$publicKeyCredential = $publicKeyCredentialLoader->load($data);
		$response            = $publicKeyCredential->getResponse();

		// Check if the response is an Authenticator Assertion Response
		if (!$response instanceof AuthenticatorAssertionResponse)
		{
			throw new \RuntimeException('Not an authenticator assertion response');
		}

		/**
		 * Check the response against the attestation request
		 *
		 * Yes, we can accept the user handle (stored in the session after evaluating the username the client used when
		 * trying to log in, if any). Even if a smart alec tries to use another user's username with their resident
		 * credential there are TWO ways we prevent them from logging into the site.
		 *
		 * First, client-side. When a username is provided we transmit a list of allowed credentials for WebAuthn
		 * authentication. Therefore the browser will reject the impersonator's security key.
		 *
		 * Second, server-side. Even if a browser bug (or a maliciously modified browser) allows the authentication to
		 * proceed with a disallowed key we have three sets of user handles: the one in the session (based on the
		 * username provided), the one from the browser's Authenticator Assertion Response and the one from the
		 * credential stored server-side at registration time. ALL THREE MUST MATCH for the check() method to succeed.
		 * In any impersonation scenario only two will match; the server-side user handle will always belong to the
		 * real user.
		 *
		 * Can this be beaten? Not plausibly. The user handle is an HMAC-SHA-256 of the numeric user ID with the site's
		 * secret key. They secret key is private. Even if the malicious user could somehow divine it and construct a
		 * malicious browser and authenticator they STILL can't beat the system because at registration time we store
		 * the user handle of the currently logged in user with the credentials. This is NOT under the control of the
		 * malicious user (unless he can already write to the site's database in which case the site is already hacked
		 * and we're discussing if you can compromise a site you have already compromised to which the answer is always
		 * yes, of course, by definition).
		 */

		/** @var AuthenticatorAssertionResponse $authenticatorAssertionResponse */
		$authenticatorAssertionResponse = $publicKeyCredential->getResponse();
		$userHandle                     = Joomla::getSessionVar('userHandle', null, 'plg_system_passwordless');
		$userHandle                     = empty($userHandle) ? null : $userHandle;

		$authenticatorAssertionResponseValidator->check(
			$publicKeyCredential->getRawId(),
			$authenticatorAssertionResponse,
			$publicKeyCredentialRequestOptions,
			$request,
			$userHandle
		);

		/**
		 * At this point we're satisfied that the response user handle (if any), the session user handle (if any) and
		 * the server-side stored credential's user handle match. Moreover, we have established that at least one of
		 * the response and session user handles is non-empty.
		 *
		 * Therefore we need to return the non-empty user handle back, whichever it is. By definition, whichever it is,
		 * it is valid, matches the stored credential and we can take it to the bank (log the respective user in)!
		 */
		$responseUserHandle = $authenticatorAssertionResponse->getUserHandle();

		return empty($responseUserHandle) ? $userHandle : $responseUserHandle;
	}

	/**
	 * Retrieve the public key credential request options saved in the session. If they do not exist or are corrupt it
	 * is a hacking attempt and we politely tell the hacker to go away.
	 *
	 * @return  PublicKeyCredentialRequestOptions
	 *
	 * @since   1.0.0
	 */
	private function getPKCredentialRequestOptions(): PublicKeyCredentialRequestOptions
	{
		$encodedOptions = Joomla::getSessionVar('publicKeyCredentialRequestOptions', null, 'plg_system_passwordless');

		if (empty($encodedOptions))
		{
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
		}

		try
		{
			$publicKeyCredentialCreationOptions = unserialize(base64_decode($encodedOptions));
		}
		catch (Exception $e)
		{
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
		}

		if (!is_object($publicKeyCredentialCreationOptions) ||
			!($publicKeyCredentialCreationOptions instanceof PublicKeyCredentialRequestOptions))
		{
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREATE_INVALID_LOGIN_REQUEST'));
		}

		return $publicKeyCredentialCreationOptions;
	}
}