<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2021 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

use Joomla\CMS\Factory;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Layout\FileLayout;
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
	'user'        => Factory::getApplication()->getIdentity() ?? new User(),
	'allow_add'   => false,
	'credentials' => [],
	'error'       => '',
	'knownAuthenticators' => [],
	'attestationSupport'  => true,
], $displayData));

// Ensure the GMP or BCmath extension (or a polyfill) is loaded in PHP - this is required by the third party library.
$hasGMP    = function_exists('gmp_intval') !== false;
$hasBcMath = function_exists('bccomp') !== false;

if ($displayData['allow_add'] === false)
{
	$error = Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CANNOT_ADD_FOR_A_USER');
	//phpcs:ignore
	$allow_add = false;
}
elseif (!$hasBcMath && !$hasBcMath)
{
	$error     = Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_WEBAUTHN_REQUIRES_GMP_OR_BCMATCH');
	$allow_add = false;
}

HTMLHelper::_('bootstrap.tooltip', '.plg_system_passwordless_tooltip');
?>
<div class="akpwl" id="plg_system_passwordless-management-interface">
	<?php if (is_string($error) && !empty($error)): ?>
		<div class="alert alert-danger">
			<?= $error ?>
		</div>
	<?php endif; ?>

	<table class="table table-striped">
		<caption class="visually-hidden">
			<?php echo Text::_('PLG_SYSTEM_PASSWORDLESS_TABLE_CAPTION'); ?>,
		</caption>
		<thead class="table-dark">
		<tr>
			<th <?php if ($attestationSupport): ?>colspan="2"<?php endif; ?> scope="col">
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
				<?php
				if ($attestationSupport):
				$aaguid = ($method['credential'] instanceof \Webauthn\PublicKeyCredentialSource) ? $method['credential']->getAaguid() : '';
				$aaguid = is_string($aaguid) ? $aaguid : $aaguid->toString();
				$authMetadata = $knownAuthenticators[$aaguid] ?? $knownAuthenticators[''];
				?>
				<td class="text-center">
					<img class="plg_system_passwordless_tooltip bg-secondary"
						 style="max-width: 6em; max-height: 3em"
						 src="<?php echo $authMetadata->icon ?>"
						 alt="<?php echo $authMetadata->description ?>"
						 title="<?php echo $authMetadata->description ?>">
				</td>
				<?php endif; ?>
				<th scope="row" class="plg_system_passwordless-cell">
					<?= htmlentities($method['label']) ?>
				</th>
				<td class="plg_system_passwordless-cell">
					<button class="plg_system_passwordless-manage-edit btn btn-secondary" type="button">
						<span class="icon-edit " aria-hidden="true"></span>
						<?= Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_EDIT_LABEL') ?>
					</button>
					<button class="plg_system_passwordless-manage-delete btn btn-danger" type="button">
						<span class="icon-minus" aria-hidden="true"></span>
						<?= Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_DELETE_LABEL') ?>
					</button>
				</td>
			</tr>
		<?php endforeach; ?>
		<?php if (empty($credentials)): ?>
			<tr>
				<td colspan="<?= $attestationSupport ? 3 : 2 ?>">
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
					class="btn btn-success w-100"
			>
				<span class="icon-plus" aria-hidden="true"></span>
				<?php echo Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_ADD_LABEL') ?>
			</button>
		</p>
	<?php endif; ?>
</div>
