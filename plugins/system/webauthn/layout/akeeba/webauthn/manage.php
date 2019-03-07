<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

use Akeeba\Passwordless\Webauthn\Helper\CredentialsCreation;
use Akeeba\Passwordless\Webauthn\Helper\Joomla;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Layout\FileLayout;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;

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
 * @var   string     $error       Any error messages
 */

// Extract the data. Do not remove until the unset() line.
extract(array_merge([
	'user'        => Joomla::getUser(),
	'allow_add'   => false,
	'credentials' => [],
	'error'       => '',
], $displayData));

HTMLHelper::_('stylesheet', 'plg_system_webauthn/backend.css', [
	'relative' => true,
]);

/**
 * Starting with PHP 5.4.0, short echo tags are always recognized and parsed regardless of the short_open_tag setting
 * in your php.ini. Since we only support *much* newer versions of PHP we can use this construct instead of regular
 * echos to keep the code easier to read.
 */
?>
<div class="akpwl" id="akpwl-management-interface">

	<?php if (is_string($error) && !empty($error)): ?>
		<div class="alert alert-error">
			<?= htmlentities($error) ?>
		</div>
	<?php endif; ?>

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

	<?php if ($allow_add):
		/**
		 * Why not push these configuration variables directly to JavaScript?
		 *
		 * We need to reload them every time we return from an attempt to authorize an authenticator. Whenever that
		 * happens we push raw HTML to the page. However, any SCRIPT tags in that HTML do not get parsed, i.e. they
		 * do not replace existing values. This causes any retries to fail. By using a data storage object we circumvent
		 * that problem.
		 */
		$randomId    = 'akpwl_' . Joomla::generateRandom(32);
		$publicKey   = base64_encode(CredentialsCreation::createPublicKey($user));
		$postbackURL = base64_encode(rtrim(Uri::base(), '/') . '/index.php?' . Joomla::getToken() . '=1');
		?>
		<span id="<?= $randomId ?>"
			data-public_key = "<?= $publicKey ?>"
			data-postback_url = "<?= $postbackURL ?>"
		></span>
		<p class="akpwl-manage-add-container">
			<a onclick="akeeba_passwordless_create_credentials('<?= $randomId ?>', '#akpwl-management-interface');"
			   class="akpwl-btn--green--block">
				<span class="icon-plus icon-white"></span>
				<?= Joomla::_('PLG_SYSTEM_WEBAUTHN_MANAGE_BTN_ADD_LABEL') ?>
			</a>
		</p>
	<?php endif; ?>
</div>
