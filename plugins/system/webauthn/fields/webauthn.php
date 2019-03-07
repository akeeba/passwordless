<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

// Prevent direct access
use Akeeba\Passwordless\Webauthn\Helper\Joomla;
use Joomla\CMS\Form\FormField;

defined('_JEXEC') or die;

class JFormFieldWebauthn extends FormField
{
	/**
	 * Element name
	 *
	 * @var   string
	 */
	protected $_name = 'Webauthn';

	function getInput()
	{
		$user_id = $this->form->getData()->get('id', null);

		if (is_null($user_id))
		{
			return Joomla::_('PLG_SYSTEM_WEBAUTHN_ERR_NOUSER');
		}

		$credentialRepository = new \Akeeba\Passwordless\Webauthn\CredentialRepository();

		return Joomla::renderLayout('akeeba.webauthn.manage', [
			'user'        => Joomla::getUser($user_id),
			'allow_add'   => $user_id == Joomla::getUser()->id,
			'credentials' => $credentialRepository->getAll($user_id),
		]);
	}
}
