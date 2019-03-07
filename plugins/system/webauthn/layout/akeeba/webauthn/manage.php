<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

use Akeeba\Passwordless\Webauthn\Helper\Joomla;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Layout\FileLayout;
use Joomla\CMS\User\User;
use Webauthn\AttestedCredentialData;

/**
 * Passwordless Login management interface
 *
 *
 * Generic data
 *
 * @var   FileLayout $this        The Joomla layout renderer
 * @var   array      $displayData The data in array format. DO NOT USE.
 *
 * Layout specific data
 *
 * @var   User       $user        The Joomla user whose passwordless login we are managing
 * @var   bool       $allow_add   Are we allowed to add passwordless login methods
 * @var   array      $credentials The already stored credentials for the user
 */

// Extract the data. Do not remove until the unset() line.
extract(array_merge([
	'user'        => Joomla::getUser(),
	'allow_add'   => false,
	'credentials' => [],
], $displayData));

HTMLHelper::_('stylesheet', 'plg_system_webauthn/backend.css', [
	'relative' => true,
]);

/**
 * Important note to those of you who will scream bloody murder at the use of "short tags":
 *
 * Starting with PHP 5.4.0, short echo tags are always recognized and parsed regardless of the short_open_tag setting
 * in your php.ini. Since we only support *much* newer versions of PHP we can use this construct instead of regular
 * echos to keep the code easier to read.
 */
?>

<div class="akpwl">
	<table class="akpwl-table--striped">
		<thead>
		<tr>
			<th><?= Joomla::_('PLG_SYSTEM_WEBAUTHN_MANAGE_FIELD_KEYLABEL_LABEL') ?></th>
			<th><?= Joomla::_('PLG_SYSTEM_WEBAUTHN_MANAGE_HEADER_ACTIONS_LABEL') ?></th>
		</tr>
		</thead>
		<tbody>
		<?php foreach ($credentials as $method): ?>
			<tr>
				<td><?= htmlentities($method['label']) ?></td>
				<td>
					<a onclick="alert('TODO');"
					   class="akpwl-btn--teal">
						<span class="icon-edit icon-white"></span>
						<?= Joomla::_('PLG_SYSTEM_WEBAUTHN_MANAGE_BTN_EDIT_LABEL') ?>
					</a>
					<a onclick="alert('TODO');"
					   class="akpwl-btn--red">
						<span class="icon-minus-sign icon-white"></span>
						<?= Joomla::_('PLG_SYSTEM_WEBAUTHN_MANAGE_BTN_DELETE_LABEL') ?>
					</a>
				</td>
			</tr>
		<?php endforeach; ?>
		<?php if (empty($credentials)): ?>
			<tr>
				<td colspan="2">
					<?= Joomla::_('PLG_SYSTEM_WEBAUTHN_MANAGE_HEADER_NOMETHODS_LABEL') ?>
				</td>
			</tr>
		<?php endif; ?>
		</tbody>
	</table>

	<?php if ($allow_add): ?>
		<p class="akpwl-manage-add-container">
			<a onclick="alert('Yoohoo');"
			   class="akpwl-btn--green--block">
				<span class="icon-plus icon-white"></span>
				<?= Joomla::_('PLG_SYSTEM_WEBAUTHN_MANAGE_BTN_ADD_LABEL') ?>
			</a>
		</p>
	<?php endif; ?>
</div>
