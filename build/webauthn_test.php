<?php

use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Model\DatabaseAwareTrait;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\Database\ParameterType;
use Joomla\Plugin\System\Passwordless\Credential\CredentialsRepository as MyCredRepo;
use Joomla\Plugin\System\Webauthn\CredentialRepository as CoreCredRepo;

// region Boilerplate
define('_JEXEC', 1);

foreach ([__DIR__, getcwd()] as $curdir)
{
	if (file_exists($curdir . '/defines.php'))
	{
		define('JPATH_BASE', realpath($curdir . '/..'));
		require_once $curdir . '/defines.php';

		break;
	}

	if (file_exists($curdir . '/../includes/defines.php'))
	{
		define('JPATH_BASE', realpath($curdir . '/..'));
		require_once $curdir . '/../includes/defines.php';

		break;
	}
}

defined('JPATH_LIBRARIES') || die ('This script must be placed in or run from the cli folder of your site.');

require_once JPATH_LIBRARIES . '/fof40/Cli/Application.php';
// endregion

error_reporting(E_ALL);
ini_set('display_errors', 1);

class WebauthnTest extends FOFApplicationCLI
{
	use DatabaseAwareTrait;

	const USER_ID = 70;

	public function __construct(\Joomla\Input\Input $input = null, \Joomla\Registry\Registry $config = null, \Joomla\CMS\Application\CLI\CliOutput $output = null, \Joomla\CMS\Application\CLI\CliInput $cliInput = null, \Joomla\Event\DispatcherInterface $dispatcher = null, \Joomla\DI\Container $container = null)
	{
		parent::__construct($input, $config, $output, $cliInput, $dispatcher, $container);

		$db = Factory::getContainer()->get('DatabaseDriver');
		$this->setDbo($db);
	}

	public function getName()
	{
		return 'cli';
	}

	public function getTemplate()
	{
		return 'system';
	}

	protected function doExecute()
	{
		PluginHelper::importPlugin('system', 'passwordless');
		PluginHelper::importPlugin('system', 'webauthn');

		$this->out('Copying over definitions');
		$this->out(str_repeat('=', 79));

		$this->copyOverDefinition(self::USER_ID);

		$this->out('');
		$this->out('Testing compatibility');
		$this->out(str_repeat('=', 79));

		$this->out('Testing Credentials Repository compatibility');
		$this->testRepositories();

		$this->out('Testing challenge creation compatibility');
		$this->testChallengeCreation();

		$this->out('');
		$this->out(str_repeat('#', 79));
		$this->out('Everything checks out!');
		$this->out(str_repeat('#', 79));
	}

	protected function testRepositories(): void
	{
		$user = Factory::getContainer()->get(UserFactoryInterface::class)->loadUserById(self::USER_ID);

		$myRepo   = new MyCredRepo();
		$coreRepo = new CoreCredRepo();

		$userEntityMine = new \Akeeba\Passwordless\Webauthn\PublicKeyCredentialUserEntity(
			$user->username,
			$myRepo->getHandleFromUserId($user->id),
			$user->name
		);
		$userEntityCore = new \Webauthn\PublicKeyCredentialUserEntity(
			$user->username,
			$coreRepo->getHandleFromUserId($user->id),
			$user->name
		);

		$myAll   = array_map(function (\Akeeba\Passwordless\Webauthn\PublicKeyCredentialSource $x) {
			return md5($x->getPublicKeyCredentialId()) . '::' . md5($x->getCredentialPublicKey());
		}, $myRepo->findAllForUserEntity($userEntityMine));
		$coreAll = array_map(function (\Webauthn\PublicKeyCredentialSource $x) {
			return md5($x->getPublicKeyCredentialId()) . '::' . md5($x->getCredentialPublicKey());
		}, $coreRepo->findAllForUserEntity($userEntityCore));

		$diff1 = array_diff($myAll, $coreAll);
		$diff2 = array_diff($coreAll, $myAll);

		if (!empty($diff1) || !empty($diff2))
		{
			$this->out('The repositories returned different Public Key Credential Sources.');

			$this->close(128);
		}
	}

	private function copyOverDefinition(int $user_id)
	{
		$myRepo = new MyCredRepo();
		$handle = $myRepo->getHandleFromUserId($user_id);

		// Get core WebAuthn authenticators
		$db      = $this->getDbo();
		$query   = $db->getQuery(true)
			->select('*')
			->from($db->quoteName('#__webauthn_credentials'))
			->where($db->quoteName('user_id') . ' = :handle')
			->bind(':handle', $handle, ParameterType::STRING);
		$objects = $db->setQuery($query)->loadObjectList();

		// Delete the Passwordless plugin's authenticators
		$query = $db->getQuery(true)
			->delete($db->quoteName('#__passwordless_credentials'))
			->where($db->quoteName('user_id') . ' = :handle')
			->bind(':handle', $handle, ParameterType::STRING);
		$db->setQuery($query)->execute();

		// Copy over the authenticators
		foreach ($objects as $o)
		{
			$db->insertObject('#__passwordless_credentials', $o);
		}
	}

	private function coreChallengeCreate(User $user)
	{
		$repository = new CoreCredRepo();
		$userId     = $user->id;

		// Load the saved credentials into an array of PublicKeyCredentialDescriptor objects
		try
		{
			$userEntity  = new \Webauthn\PublicKeyCredentialUserEntity(
				'', $repository->getHandleFromUserId($userId), ''
			);
			$credentials = $repository->findAllForUserEntity($userEntity);
		}
		catch (Exception $e)
		{
			return null;
		}

		// No stored credentials?
		if (empty($credentials))
		{
			return null;
		}

		$registeredPublicKeyCredentialDescriptors = [];

		/** @var \Webauthn\PublicKeyCredentialSource $record */
		foreach ($credentials as $record)
		{
			try
			{
				$registeredPublicKeyCredentialDescriptors[] = $record->getPublicKeyCredentialDescriptor();
			}
			catch (Throwable $e)
			{
				continue;
			}
		}

		// Extensions
		$extensions = new \Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs();

		// Public Key Credential Request Options
		$publicKeyCredentialRequestOptions = new \Webauthn\PublicKeyCredentialRequestOptions(
			random_bytes(32),
			60000,
			Uri::getInstance()->toString(['host']),
			$registeredPublicKeyCredentialDescriptors,
			\Webauthn\PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
			$extensions
		);

		return $publicKeyCredentialRequestOptions;
	}

	private function testChallengeCreation(): void
	{
		$_SERVER['HTTPS']       = true;
		$_SERVER['HTTP_HOST']   = 'boot4.local.web';
		$_SERVER['REQUEST_URI'] = '/index.php';
		$_SERVER['PHP_SELF']    = 'index.php';

		$user = Factory::getContainer()->get(UserFactoryInterface::class)->loadUserById(self::USER_ID);
		$mine = \Joomla\Plugin\System\Passwordless\Credential\Authentication::getPubkeyRequestOptions($user);
		$core = $this->coreChallengeCreate($user);

		$myAllowed   = array_map(function (\Akeeba\Passwordless\Webauthn\PublicKeyCredentialDescriptor $x) {
			return base64_encode($x->getId());
		}, $mine->getAllowCredentials());
		$coreAllowed = array_map(function (\Webauthn\PublicKeyCredentialDescriptor $x) {
			return base64_encode($x->getId());
		}, $core->getAllowCredentials());

		$diff1 = array_diff($myAllowed, $coreAllowed);
		$diff2 = array_diff($coreAllowed, $myAllowed);

		if (!empty($diff1) || !empty($diff2))
		{
			$this->out('The allowed credentials returned differ.');

			$this->out('Mine:');
			foreach ($myAllowed as $x)
			{
				$this->out("\t" . $x);
			}

			$this->out('Core:');
			foreach ($coreAllowed as $x)
			{
				$this->out("\t" . $x);
			}

			$this->close(128);
		}
	}
}

FOFApplicationCLI::getInstance('WebauthnTest')->execute();