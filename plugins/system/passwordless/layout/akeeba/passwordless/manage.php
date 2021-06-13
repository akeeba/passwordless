<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2021 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

use Akeeba\Passwordless\Helper\CredentialsCreation;
use Akeeba\Passwordless\Helper\Joomla;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Layout\FileLayout;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserHelper;

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

/**
 * Note about the use of short echo tags.
 *
 * Starting with PHP 5.4.0, short echo tags are always recognized and parsed regardless of the short_open_tag setting
 * in your php.ini. Since we only support *much* newer versions of PHP we can use this construct instead of regular
 * echos to keep the code easier to read.
 */

// Extract the data. Do not remove until the unset() line.
extract(array_merge([
	'user'        => Joomla::getUser(),
	'allow_add'   => false,
	'credentials' => [],
	'error'       => '',
], $displayData));

if (version_compare(JVERSION, '3.999.999', 'le'))
{
	HTMLHelper::_('stylesheet', 'plg_system_passwordless/backend.css', [
		'relative' => true,
	]);
}

// Ensure the GMP Extension is loaded in PHP - as this is required by third party library
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
$publicKey   = $allow_add ? base64_encode(CredentialsCreation::createPublicKey($user)) : '{}';
$postbackURL = base64_encode(rtrim(Uri::base(), '/') . '/index.php?' . Joomla::getToken() . '=1');
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

	<table class="akpwl-table--striped table table-striped">
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
							class="plg_system_passwordless-manage-edit akpwl-btn--teal btn btn-primary btn-sm">
						<span class="icon-edit icon-white" aria-hidden="true"></span>
						<?= Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_EDIT_LABEL') ?>
					</button>
					<button data-random-id="<?php echo $randomId; ?>"
							class="plg_system_passwordless-manage-delete akpwl-btn--red btn btn-danger btn-sm">
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
					class="akpwl-btn--green--block btn btn-success"
					data-random-id="<?php echo $randomId; ?>">
				<span class="icon-plus icon-white" aria-hidden="true"></span>
				<?php echo Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_ADD_LABEL') ?>
			</button>
		</p>
	<?php endif; ?>
</div>
