<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2021 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

use Joomla\CMS\Application\CMSApplication;
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
 * @var   FileLayout     $this        The Joomla layout renderer
 * @var   array          $displayData The data in array format. DO NOT USE.
 *
 * Layout specific data
 *
 * @var   User           $user        The Joomla user whose passwordless login we are managing
 * @var   bool           $allow_add   Are we allowed to add passwordless login methods
 * @var   array          $credentials The already stored credentials for the user
 * @var   string         $error       Any error messages
 * @var   bool           $showImages  Should I show maker logos next to the registered authenticators?
 * @var   CMSApplication $application The application
 */

// Extract the data. Do not remove until the unset() line.
extract(array_merge([
	'user'                => null,
	'allow_add'           => false,
	'credentials'         => [],
	'error'               => '',
	'showImages'          => true,
], $displayData));

$user ??= $application->getIdentity();

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
			<th scope="col">
				<?= Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_FIELD_KEYLABEL_LABEL') ?>
			</th>
			<th scope="col" class="text-end">
				<?= Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_HEADER_ACTIONS_LABEL') ?>
			</th>
		</tr>
		</thead>
		<tbody>
		<?php foreach ($credentials as $method): ?>
			<tr data-credential_id="<?= $method['id'] ?>">
				<th scope="row" class="plg_system_passwordless-cell">
					<span class="plg_system_passwordless-label flex-grow-1">
						<?= htmlentities($method['label']) ?>
					</span>
				</th>
				<td class="plg_system_passwordless-cell w-35 text-end">
					<button class="plg_system_passwordless-manage-edit btn btn-secondary m-1" type="button">
						<span class="icon-edit " aria-hidden="true"></span>
						<?= Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_EDIT_LABEL') ?>
					</button>
					<button class="plg_system_passwordless-manage-delete btn btn-danger m-1" type="button">
						<span class="icon-minus" aria-hidden="true"></span>
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
		<div class="akpwl-manage-add-container mt-3 mb-2 d-flex">
			<div class="flex-grow-1 mx-2 d-flex flex-column align-items-center">
				<button
						type="button"
						id="plg_system_passwordless-manage-addresident"
						class="btn btn-dark w-100"
				>
					<?= file_get_contents(JPATH_ROOT . '/media/plg_system_passwordless/images/passkey-white.svg') ?: '' ?>
					<span class="ms-1">
						<?php echo Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_ADDRESIDENT_LABEL') ?>
					</span>
				</button>
			</div>

			<div class="flex-grow-1 mx-2 d-flex flex-column align-items-center">
				<button
						type="button"
						id="plg_system_passwordless-manage-add"
						class="btn btn-outline-dark w-100"
				>
					<?= file_get_contents(JPATH_ROOT . '/media/plg_system_passwordless/images/webauthn.svg') ?: '' ?>
					<span class="ms-1">
						<?php echo Text::_('PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_ADD_LABEL') ?>
					</span>
				</button>
			</div>

		</div>
	<?php endif; ?>
</div>
