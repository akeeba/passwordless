<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2021 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Layout\FileLayout;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserHelper;
use Joomla\Plugin\System\Passwordless\Credential\Authentication;

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
	'user'        => Factory::getApplication()->getIdentity() ?? new User(),
	'allow_add'   => false,
	'credentials' => [],
	'error'       => '',
], $displayData));

// Ensure the GMP or BCmath extension (or a polyfill) is loaded in PHP - this is required by the third party library.
$hasGMP    = function_exists('gmp_intval') !== false;
$hasBcMath = function_exists('bccomp') !== false;

if (!$hasBcMath && !$hasBcMath)
{
	$error     = Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_WEBAUTHN_REQUIRES_GMP_OR_BCMATCH');
	$allow_add = false;
}

/**
 * Why not push these configuration variables directly to JavaScript?
 *
 * We need to reload them every time we return from an attempt to authorize an authenticator. Whenever that
 * happens we push raw HTML to the page. However, any SCRIPT tags in that HTML do not get parsed, i.e. they
 * do not replace existing values. This causes any retries to fail. By using a data storage object we circumvent
 * that problem.
 */
$randomId    = 'akpwl_' . UserHelper::genRandomPassword(32);
$publicKey   = base64_encode($allow_add ? json_encode(Authentication::getPubKeyCreationOptions($user), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : '{}');
$postbackURL = base64_encode(rtrim(Uri::base(), '/') . '/index.php?' . Factory::getApplication()->getFormToken() . '=1');
?>
<div class="akpwl" id="plg_system_passwordless-management-interface">
    <span id="<?= $randomId ?>"
		  data-public_key="<?= $publicKey ?>"
		  data-postback_url="<?= $postbackURL ?>"
	></span>

	<?php if (is_string($error) && !empty($error)): ?>
		<div class="akpwn-block--error alert alert-danger">
			<?= $error ?>
		</div>
	<?php endif; ?>

	<table class="table table-striped">
		<thead>
		<tr>
			<th scope="col">
				<?= Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_FIELD_KEYLABEL_LABEL') ?>
			</th>
			<th scope="col">
				<?= Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_HEADER_ACTIONS_LABEL') ?>

			</th>
		</tr>
		</thead>
		<tbody>
		<?php foreach ($credentials as $method): ?>
			<tr data-credential_id="<?= $method['id'] ?>">
				<td>
					<?= htmlentities($method['label']) ?>
				</td>
				<td>
					<button data-random-id="<?php echo $randomId; ?>"
							class="plg_system_passwordless-manage-edit btn btn-primary btn-sm">
						<span class="icon-edit icon-white" aria-hidden="true"></span>
						<?= Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_EDIT_LABEL') ?>
					</button>
					<button data-random-id="<?php echo $randomId; ?>"
							class="plg_system_passwordless-manage-delete btn btn-danger btn-sm">
						<span class="icon-minus-sign icon-white" aria-hidden="true"></span>
						<?= Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_DELETE_LABEL') ?>
					</button>
				</td>
			</tr>
		<?php endforeach; ?>
		<?php if (empty($credentials)): ?>
			<tr>
				<td colspan="2">
					<?= Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_HEADER_NOMETHODS_LABEL') ?>
				</td>
			</tr>
		<?php endif; ?>
		</tbody>
	</table>

	<?php if ($allow_add): ?>
		<p class="akpwl-manage-add-container">
			<button
					type="button"
					id="plg_system_passwordless-manage-add"
					class="btn btn-success"
					data-random-id="<?php echo $randomId; ?>">
				<span class="icon-plus icon-white" aria-hidden="true"></span>
				<?php echo Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_ADD_LABEL') ?>
			</button>
		</p>
	<?php endif; ?>
</div>
