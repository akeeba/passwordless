<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2021 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

// Prevent direct access
use Akeeba\Passwordless\Helper\Joomla;
use Joomla\CMS\Form\FormField;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;

defined('_JEXEC') or die;

class JFormFieldPasswordless extends FormField
{
	/**
	 * Element name
	 *
	 * @var   string
	 */
	protected $_name = 'Passwordless';

	function getInput()
	{
		$user_id = $this->form->getData()->get('id', null);

		if (is_null($user_id))
		{
			return Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_NOUSER');
		}

		Text::script('PLG_SYSTEM_PASSWORDLESS_ERR_NO_BROWSER_SUPPORT', true);
		Text::script('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_SAVE_LABEL', true);
		Text::script('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_CANCEL_LABEL', true);
		Text::script('PLG_SYSTEM_PASSWORDLESS_MSG_SAVED_LABEL', true);
		Text::script('PLG_SYSTEM_PASSWORDLESS_ERR_LABEL_NOT_SAVED', true);
		Text::script('PLG_SYSTEM_PASSWORDLESS_ERR_NOT_DELETED', true);

		$credentialRepository = new \Akeeba\Passwordless\CredentialRepository();

		HTMLHelper::_('script', 'plg_system_passwordless/dist/passwordless.js', [
			'relative'  => true,
			'framework' => false,
		], [
			'defer' => true
		]);

		return Joomla::renderLayout('akeeba.passwordless.manage', [
			'user'        => Joomla::getUser($user_id),
			'allow_add'   => $user_id == Joomla::getUser()->id,
			'credentials' => $credentialRepository->getAll($user_id),
		]);
	}
}
