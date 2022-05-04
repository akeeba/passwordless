<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Joomla\Plugin\System\Passwordless\Field;

// Prevent direct access
defined('_JEXEC') or die;

use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Factory;
use Joomla\CMS\Form\FormField;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Layout\FileLayout;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\Plugin\System\Passwordless\Extension\Passwordless;


class PasswordlessField extends FormField
{
	/**
	 * Element name
	 *
	 * @var   string
	 */
	protected $_name = 'Passwordless';

	function getInput()
	{
		$userId = $this->form->getData()->get('id', null);

		if (is_null($userId))
		{
			return Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_NOUSER');
		}

		Text::script('PLG_SYSTEM_PASSWORDLESS_ERR_NO_BROWSER_SUPPORT', true);
		Text::script('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_SAVE_LABEL', true);
		Text::script('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_CANCEL_LABEL', true);
		Text::script('PLG_SYSTEM_PASSWORDLESS_MSG_SAVED_LABEL', true);
		Text::script('PLG_SYSTEM_PASSWORDLESS_ERR_LABEL_NOT_SAVED', true);
		Text::script('PLG_SYSTEM_PASSWORDLESS_ERR_NOT_DELETED', true);
		Text::script('PLG_SYSTEM_PASSWORDLESS_ERR_XHR_INITCREATE', true);

		/** @var CMSApplication $app */
		$app = Factory::getApplication();
		/** @var Passwordless $plugin */
		$plugin = $app->bootPlugin('passwordless', 'system');

		$wam = $app->getDocument()->getWebAssetManager();
		$wam->getRegistry()->addExtensionRegistryFile('plg_system_passwordless');
		$wam->useScript('plg_system_passwordless.manage');

		$layoutFile = new FileLayout('akeeba.passwordless.manage', JPATH_PLUGINS . '/system/passwordless/layout');

		$authenticationHelper
			= $plugin->getAuthenticationHelper();

		return $layoutFile->render([
			'user'                => Factory::getContainer()
			                                ->get(UserFactoryInterface::class)
			                                ->loadUserById($userId),
			'allow_add'           => $userId == $app->getIdentity()->id,
			'credentials'         => $authenticationHelper->getCredentialsRepository()->getAll($userId),
			'knownAuthenticators' => $authenticationHelper->getKnownAuthenticators(),
			'attestationSupport'  => $authenticationHelper->hasAttestationSupport(),
			'allowResident'       => $plugin->params->get('allowResident', 1) == 1,
		]);
	}
}
