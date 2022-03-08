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

use Akeeba\Passwordless\Webauthn\PublicKeyCredentialDescriptor;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialRequestOptions;
use Akeeba\Passwordless\Webauthn\PublicKeyCredentialUserEntity;
use Exception;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\Plugin\System\Passwordless\Credential\CredentialsRepository;
use RuntimeException;

/**
 * Base class for all authentication helpers
 *
 * @since  1.0.0
 */
abstract class AbstractAuthentication implements AuthenticationInterface
{
	/**
	 * The credentials repository
	 *
	 * @var   CredentialsRepository
	 * @since 1.0.0
	 */
	protected static $credentialsRepository;

	/**
	 * Get the user's avatar (through Gravatar)
	 *
	 * @param   User   $user   The Joomla user object
	 * @param   int    $size   The dimensions of the image to fetch (default: 64 pixels)
	 *
	 * @return  string  The URL to the user's avatar
	 *
	 * @since   1.0.0
	 */
	protected function getAvatar(User $user, int $size = 64)
	{
		$scheme    = Uri::getInstance()->getScheme();
		$subdomain = ($scheme == 'https') ? 'secure' : 'www';

		return sprintf('%s://%s.gravatar.com/avatar/%s.jpg?s=%u&d=mm', $scheme, $subdomain, md5($user->email), $size);
	}

	/**
	 * Try to find the site's favicon in the site's root, images, media, templates or current template directory.
	 *
	 * @return  string|null
	 *
	 * @since   1.0.0
	 */
	protected function getSiteIcon(): ?string
	{
		$filenames = [
			'apple-touch-icon.png',
			'apple_touch_icon.png',
			'favicon.ico',
			'favicon.png',
			'favicon.gif',
			'favicon.bmp',
			'favicon.jpg',
			'favicon.svg',
		];

		try
		{
			$paths = [
				'/',
				'/images/',
				'/media/',
				'/templates/',
				'/templates/' . Factory::getApplication()->getTemplate(),
			];
		}
		catch (Exception $e)
		{
			return null;
		}

		foreach ($paths as $path)
		{
			foreach ($filenames as $filename)
			{
				$relFile  = $path . $filename;
				$filePath = JPATH_BASE . $relFile;

				if (is_file($filePath))
				{
					break 2;
				}

				$relFile = null;
			}
		}

		if (is_null($relFile))
		{
			return null;
		}

		return rtrim(Uri::base(), '/') . '/' . ltrim($relFile, '/');
	}

	/**
	 * Get the credentials repository
	 *
	 * @return  CredentialsRepository
	 *
	 * @since   1.0.0
	 */
	protected function getCredentialsRepository(): CredentialsRepository
	{
		if (self::$credentialsRepository !== null)
		{
			return self::$credentialsRepository;
		}

		self::$credentialsRepository = new CredentialsRepository();

		return self::$credentialsRepository;
	}

	/**
	 * Returns a User Entity object given a Joomla user
	 *
	 * @param   User   $user
	 *
	 * @return  PublicKeyCredentialUserEntity
	 *
	 * @since   1.0.0
	 */
	protected function getUserEntity(User $user): PublicKeyCredentialUserEntity
	{
		$repository = $this->getCredentialsRepository();

		return new PublicKeyCredentialUserEntity(
			$user->username,
			$repository->getHandleFromUserId($user->id),
			$user->name,
			$this->getAvatar($user, 64)
		);
	}

	/**
	 * Returns an array of the PK credential descriptors (registered authenticators) for the given user.
	 *
	 * @param   User   $user
	 *
	 * @return  PublicKeyCredentialDescriptor[]
	 *
	 * @since   1.0.0
	 */
	protected function getPubKeyDescriptorsForUser(User $user): array
	{
		$userEntity  = $this->getUserEntity($user);
		$repository  = $this->getCredentialsRepository();
		$descriptors = [];
		$records     = $repository->findAllForUserEntity($userEntity);

		foreach ($records as $record)
		{
			$descriptors[] = $record->getPublicKeyCredentialDescriptor();
		}

		return $descriptors;
	}

	/**
	 * Retrieve the public key credential request options saved in the session.
	 *
	 * If they do not exist or are corrupt it is a hacking attempt and we politely tell the attacker to go away.
	 *
	 * @return  PublicKeyCredentialRequestOptions
	 *
	 * @throws  Exception
	 * @since   1.0.0
	 */
	protected function getPKCredentialRequestOptions(): PublicKeyCredentialRequestOptions
	{
		$encodedOptions = Factory::getApplication()->getSession()->get('plg_system_passwordless.publicKeyCredentialRequestOptions', null);

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