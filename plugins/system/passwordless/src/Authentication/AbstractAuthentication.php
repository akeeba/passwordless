<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2023 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

/**
 * @package         Joomla.Plugin
 * @subpackage      System.Webauthn
 *
 * @copyright   (C) 2020 Open Source Matters, Inc. <https://www.joomla.org>
 * @license         GNU General Public License version 2 or later; see LICENSE.txt
 */

namespace Akeeba\Plugin\System\Passwordless\Authentication;

defined('_JEXEC') or die();

use Exception;
use Joomla\Application\ApplicationInterface;
use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\Session\SessionInterface;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Helper class to aid in credentials creation (link an authenticator to a user account)
 *
 * @since   2.0.0
 */
abstract class AbstractAuthentication implements AuthenticationInterface
{
	/**
	 * The credentials repository
	 *
	 * @var   PublicKeyCredentialSourceRepository
	 * @since 2.0.0
	 */
	protected PublicKeyCredentialSourceRepository $credentialsRepository;

	/**
	 * The application we are running in.
	 *
	 * @var   CMSApplication
	 * @since 2.0.0
	 */
	protected ApplicationInterface $app;

	/**
	 * The application session
	 *
	 * @var   SessionInterface
	 * @since 2.0.0
	 */
	protected SessionInterface $session;

	/**
	 * Public constructor.
	 *
	 * @param   ApplicationInterface|null                 $app       The app we are running in
	 * @param   SessionInterface|null                     $session   The app session object
	 * @param   PublicKeyCredentialSourceRepository|null  $credRepo  Credentials repo
	 *
	 * @since   2.0.0
	 */
	final public function __construct(
		?ApplicationInterface                $app = null,
		?SessionInterface                    $session = null,
		?PublicKeyCredentialSourceRepository $credRepo = null
	)
	{
		$this->app                   = $app;
		$this->session               = $session;
		$this->credentialsRepository = $credRepo;
	}

	final public static function create(
		?ApplicationInterface                $app = null,
		?SessionInterface                    $session = null,
		?PublicKeyCredentialSourceRepository $credRepo = null
	)
	{
		if (!class_exists(\Webauthn\Server::class))
		{
			// TODO LibraryV4 support…
		}

		return new LibraryV3($app, $session, $credRepo);
	}

	/**
	 * Returns the Public Key credential source repository object
	 *
	 * @return  PublicKeyCredentialSourceRepository|null
	 *
	 * @since   2.0.0
	 */
	final public function getCredentialsRepository(): ?PublicKeyCredentialSourceRepository
	{
		return $this->credentialsRepository;
	}

	/**
	 * Returns a User Entity object given a Joomla user
	 *
	 * @param   User  $user  The Joomla user to get the user entity for
	 *
	 * @return  PublicKeyCredentialUserEntity
	 *
	 * @since   2.0.0
	 */
	final public function getUserEntity(User $user): PublicKeyCredentialUserEntity
	{
		$repository = $this->credentialsRepository;

		return new PublicKeyCredentialUserEntity(
			$user->username,
			$repository->getHandleFromUserId($user->id),
			$user->name,
			$this->getAvatar($user, 64)
		);
	}

	/**
	 * Try to find the site's favicon in the site's root, images, media, templates or current
	 * template directory.
	 *
	 * @return  string|null
	 *
	 * @since   2.0.0
	 */
	final protected function getSiteIcon(): ?string
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
				'/templates/' . $this->app->getTemplate(),
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

		if (!isset($relFile) || \is_null($relFile))
		{
			return null;
		}

		return rtrim(Uri::base(), '/') . '/' . ltrim($relFile, '/');
	}

	/**
	 * Get the user's avatar (through Gravatar)
	 *
	 * @param   User  $user  The Joomla user object
	 * @param   int   $size  The dimensions of the image to fetch (default: 64 pixels)
	 *
	 * @return  string  The URL to the user's avatar
	 *
	 * @since   2.0.0
	 */
	final protected function getAvatar(User $user, int $size = 64)
	{
		$scheme    = Uri::getInstance()->getScheme();
		$subdomain = ($scheme == 'https') ? 'secure' : 'www';

		return sprintf('%s://%s.gravatar.com/avatar/%s.jpg?s=%u&d=mm', $scheme, $subdomain, md5($user->email), $size);
	}

	/**
	 * Returns an array of the PK credential descriptors (registered authenticators) for the given
	 * user.
	 *
	 * @param   User  $user  The Joomla user to get the PK descriptors for
	 *
	 * @return  PublicKeyCredentialDescriptor[]
	 *
	 * @since   2.0.0
	 */
	final protected function getPubKeyDescriptorsForUser(User $user): array
	{
		$userEntity  = $this->getUserEntity($user);
		$repository  = $this->credentialsRepository;
		$descriptors = [];
		$records     = $repository->findAllForUserEntity($userEntity);

		foreach ($records as $record)
		{
			$descriptors[] = $record->getPublicKeyCredentialDescriptor();
		}

		return $descriptors;
	}
}
