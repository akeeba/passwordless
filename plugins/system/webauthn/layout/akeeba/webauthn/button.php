<?php

use Akeeba\Passwordless\Webauthn\Helper\Joomla;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Layout\FileLayout;
use Joomla\CMS\Uri\Uri;

/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

/**
 * Passwordless Login button
 *
 * Displays the Webauthn login button which is injected in login modules
 *
 * Generic data
 *
 * @var   FileLayout $this         The Joomla layout renderer
 * @var   array      $displayData  The data in array format. DO NOT USE.
 *
 * Layout specific data
 *
 * @var   string     $class        The button class
 * @var   string     $image        An image file relative path (passed to JHtml::image)
 * @var   string     $icon         An icon class to be used instead of the image (if provided)
 */

/**
 * Note about the use of short echo tags.
 *
 * Starting with PHP 5.4.0, short echo tags are always recognized and parsed regardless of the short_open_tag setting
 * in your php.ini. Since we only support *much* newer versions of PHP we can use this construct instead of regular
 * echos to keep the code easier to read.
 */

// Extract the data. Do not remove until the unset() line.
extract(array_merge([
	'class' => 'akeeba-passwordless-login-button',
	'image' => 'plg_system_webauthn/webauthn-black.png',
	'icon'  => '',
], $displayData));

$uri = new Uri(Uri::base() . 'index.php');
$uri->setVar(Joomla::getToken(), '1');

?>
<button class="<?= $class ?> hasTooltip"
        onclick="return akeeba_passwordless_login(this, '<?= $uri->toString() ?>')"
        title="<?= Joomla::_('PLG_SYSTEM_WEBAUTHN_LOGIN_DESC') ?>">
	<?php if (!empty($icon)): ?>
        <span class="<?= $icon ?>"></span>
	<?php elseif (!empty($image)): ?>
		<?= HTMLHelper::_('image', $image, Joomla::_('PLG_SYSTEM_WEBAUTHN_LOGIN_DESC'), [
			'class' => 'icon',
		], true) ?>
	<?php endif; ?>
	<?= Joomla::_('PLG_SYSTEM_WEBAUTHN_LOGIN_LABEL') ?>
</button>
