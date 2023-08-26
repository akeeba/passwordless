<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

defined('_JEXEC') || die;

use Akeeba\Plugin\System\Passwordless\Authentication\AbstractAuthentication;
use Akeeba\Plugin\System\Passwordless\Authentication\AuthenticationInterface;
use Akeeba\Plugin\System\Passwordless\CredentialRepository;
use Akeeba\Plugin\System\Passwordless\Extension\Passwordless;
use Joomla\Application\ApplicationInterface;
use Joomla\Application\SessionAwareWebApplicationInterface;
use Joomla\CMS\Application\CMSApplicationInterface;
use Joomla\CMS\Extension\PluginInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Database\DatabaseInterface;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;
use Joomla\Event\DispatcherInterface;
use Joomla\Session\SessionInterface;
use Webauthn\PublicKeyCredentialSourceRepository;

return new class implements ServiceProviderInterface {
	/**
	 * Registers the service provider with a DI container.
	 *
	 * @param   Container  $container  The DI container.
	 *
	 * @return  void
	 *
	 * @since   7.0.0
	 */
	public function register(Container $container)
	{
		$container->set(
			PluginInterface::class,
			function (Container $container) {
				$config  = (array) PluginHelper::getPlugin('system', 'passwordless');
				$subject = $container->get(DispatcherInterface::class);

				$app     = $container->has(ApplicationInterface::class) ? $container->has(ApplicationInterface::class) : $this->getApplication();
				$session = $container->has('session') ? $container->get('session') : $this->getSession($app);

				$db                    = $container->get(DatabaseInterface::class);
				$credentialsRepository = $container->has(PublicKeyCredentialSourceRepository::class)
					? $container->get(PublicKeyCredentialSourceRepository::class)
					: new CredentialRepository($db);
				$authenticationHelper  = $container->has(AuthenticationInterface::class)
					? $container->get(AuthenticationInterface::class)
					: AbstractAuthentication::create($app, $session, $credentialsRepository);

				$plugin = new Passwordless($subject, $config);

				$plugin->setUpLogging();
				$plugin->setAuthenticationHelper($authenticationHelper);
				$plugin->setApplication(Factory::getApplication());
				$plugin->setDatabase($db);

				return $plugin;
			}
		);
	}

	/**
	 * Get the current CMS application interface.
	 *
	 * @return CMSApplicationInterface|null
	 *
	 * @since  2.0.0
	 */
	private function getApplication(): ?CMSApplicationInterface
	{
		try
		{
			$app = Factory::getApplication();
		}
		catch (Exception $e)
		{
			return null;
		}

		return ($app instanceof CMSApplicationInterface) ? $app : null;
	}

	/**
	 * Get the current application session object
	 *
	 * @param   ApplicationInterface  $app  The application we are running in
	 *
	 * @return SessionInterface|null
	 *
	 * @since  2.0.0
	 */
	private function getSession(?ApplicationInterface $app = null): ?SessionInterface
	{
		$app = $app ?? $this->getApplication();

		return $app instanceof SessionAwareWebApplicationInterface ? $app->getSession() : null;
	}
};
