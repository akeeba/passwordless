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
use Joomla\CMS\Version;

defined('_JEXEC') or die;

\Joomla\CMS\Form\FormHelper::loadFieldClass('hidden');

/**
 * A hidden field with the Joomla major version.
 *
 * Allows me to show and hide items in the interface.
 *
 * Class JFormFieldAkpwjver
 */
class JFormFieldAkpwjver extends JFormFieldHidden
{
	/**
	 * Element name
	 *
	 * @var   string
	 */
	protected $_name = 'Akpwjver';

	function getInput()
	{
		$this->setValue(Version::MAJOR_VERSION);

		return parent::getInput();
	}
}
