<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

/**
 * @package     Joomla\Plugin\System\Passwordless\Credential\Authentication
 * @subpackage
 *
 * @copyright   A copyright
 * @license     A "Slug" license name e.g. GPL2
 */

namespace Joomla\Plugin\System\Passwordless\Credential\Authentication;

use Akeeba\Passwordless\Webauthn\PublicKeyCredentialCreationOptions;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialRequestOptions;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialSource;
use Exception;
use Joomla\CMS\User\User;

/**
 * Interface to the authentication helper
 */
interface AuthenticationInterface
{
	/**
	 * Generate the public key creation options.
	 *
	 * This is used for the first step of attestation (key registration).
	 *
	 * The PK creation options and the user ID are stored in the session.
	 *
	 * @param   User   $user   The Joomla user to create the public key for
	 *
	 * @return  PublicKeyCredentialCreationOptions
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	public function getPubKeyCreationOptions(User $user): PublicKeyCredentialCreationOptions;

	/**
	 * Get the public key request options.
	 *
	 * This is used in the first step of the assertion (login) flow.
	 *
	 * @param   User   $user
	 *
	 * @return  PublicKeyCredentialRequestOptions
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	public function getPubkeyRequestOptions(User $user): ?PublicKeyCredentialRequestOptions;

	/**
	 * Validate the authenticator assertion.
	 *
	 * This is used in the second step of the assertion (login) flow. The server verifies that the assertion generated
	 * by the authenticator has not been tampered with.
	 *
	 * @param   string                              $data                                The data must already be
	 *                                                                                   DECODED from base64
	 * @param   PublicKeyCredentialRequestOptions   $publicKeyCredentialRequestOptions   The PK credential requests
	 *                                                                                   options sent to the browser
	 *                                                                                   and saved in the session when
	 *                                                                                   we started the login process.
	 *
	 * @return  PublicKeyCredentialSource
	 *
	 * @throws Exception
	 * @since   1.0.0
	 */
	public function validateAssertionResponse(string $data, PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions): PublicKeyCredentialSource;

	/**
	 * Validate the authenticator attestation.
	 *
	 * This is used for the second step of attestation (key registration), when the user has interacted with the
	 * authenticator and we need to validate the legitimacy of its response.
	 *
	 * An exception will be returned on error. Also, under very rare conditions, you may receive NULL instead of
	 * a PublicKeyCredentialSource object which means that something was off in the returned data from the browser.
	 *
	 * @param   string                               $data                                 The DECODED (from base64)
	 *                                                                                     data returned by the browser
	 *                                                                                     during the attestation
	 *                                                                                     ceremony.
	 * @param   PublicKeyCredentialCreationOptions   $publicKeyCredentialCreationOptions   The unserialised public key
	 *                                                                                     credential creation options
	 *                                                                                     from the user session.
	 *
	 * @return  PublicKeyCredentialSource|null
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	public function validateAttestationResponse(string $data, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions): ?PublicKeyCredentialSource;
}