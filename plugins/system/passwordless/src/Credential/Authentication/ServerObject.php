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

use Akeeba\Passwordless\Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Akeeba\Passwordless\Webauthn\AuthenticatorSelectionCriteria;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialCreationOptions;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialRequestOptions;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialRpEntity;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialSource;
use Akeeba\Passwordless\Webauthn\Server;
use Exception;
use Joomla\CMS\Factory;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Laminas\Diactoros\ServerRequestFactory;

/**
 * An authentication helper using the WebAuthn Server class (supposedly the easiest way to implement WebAuthn support)
 *
 * @since  1.0.0
 */
final class ServerObject extends AbstractAuthentication
{
	/** @inheritdoc */
	public function getPubKeyCreationOptions(User $user): PublicKeyCredentialCreationOptions
	{
		return $this->getWebauthnServer()->generatePublicKeyCredentialCreationOptions(
			$this->getUserEntity($user),
			PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
			$this->getPubKeyDescriptorsForUser($user),
			new AuthenticatorSelectionCriteria(
				AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
				false,
				AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED
			),
			new AuthenticationExtensionsClientInputs()
		);
	}

	/** @inheritdoc */
	public function getPubkeyRequestOptions(User $user): ?PublicKeyCredentialRequestOptions
	{
		return $this->getWebauthnServer()->generatePublicKeyCredentialRequestOptions(
			PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
			$this->getPubKeyDescriptorsForUser($user)
		);
	}

	/** @inheritdoc */
	public function validateAssertionResponse(string $data, PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions): PublicKeyCredentialSource
	{
		return $this->getWebauthnServer()->loadAndCheckAssertionResponse(
			$data,
			$this->getPKCredentialRequestOptions(),
			Factory::getApplication()->getSession()->get('plg_system_passwordless.userHandle', null) ?: null,
			ServerRequestFactory::fromGlobals()
		);
	}

	/** @inheritdoc */
	public function validateAttestationResponse(string $data, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions): ?PublicKeyCredentialSource
	{
		// We init the PSR-7 request object using Diactoros
		return $this->getWebauthnServer()->loadAndCheckAttestationResponse(
			base64_decode($data),
			$publicKeyCredentialCreationOptions,
			ServerRequestFactory::fromGlobals()
		);
	}

	/**
	 * Get the WebAuthn server object
	 *
	 * @return  Server
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	private function getWebauthnServer(): Server
	{
		$app      = Factory::getApplication();
		$siteName = $app->get('sitename');

		// Credentials repository
		$repository = $this->getCredentialsRepository();

		// Relaying Party -- Our site
		$rpEntity = new PublicKeyCredentialRpEntity(
			$siteName,
			Uri::getInstance()->toString(['host']),
			$this->getSiteIcon()
		);

		$server = new Server($rpEntity, $repository);

		/**
		 * =============================================================================================================
		 * Note about the metadata repository.
		 * =============================================================================================================
		 *
		 * We do not need to implement an MDS repo since we are not asking for the attestation metadata in this plugin.
		 * If you need to use this plugin in a high security environment you need to fork this plugin and do two things:
		 *
		 * 1. Change ATTESTATION_CONVEYANCE_PREFERENCE_NONE to ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT or
		 *    ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT in the getPubKeyCreationOptions() method.
		 * 2. Implement your own Metadata Statement (MDS) repository and set it here, e.g.
		 *    ```php
		 *    $server->setMetadataStatementRepository(new MyMDSRepository());
		 *    ```
		 * The implementation of the MDS repository is considered out-of-scope since you'd need the MDS from the
		 * manufacturer(s) of your authenticator.
		 *
		 * @see https://webauthn-doc.spomky-labs.com/deep-into-the-framework/attestation-and-metadata-statement
		 */

		// Add the Joomla logger to the Server object -- NO! This causes deprecated notices because... Joomla :(
		// $server->setLogger(Log::createDelegatedLogger());

		// Ed25519 is only available with libsodium
		if (!function_exists('sodium_crypto_sign_seed_keypair'))
		{
			$server->setSelectedAlgorithms(['RS256', 'RS512', 'PS256', 'PS512', 'ES256', 'ES512']);
		}

		return $server;
	}
}