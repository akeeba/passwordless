<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Passwordless\Webauthn;

use Exception;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\User\User;
use RuntimeException;
use Webauthn\AttestedCredentialData;
use Webauthn\CredentialRepository as CredentialRepositoryInterface;

// Protect from unauthorized access
defined('_JEXEC') or die();

class CredentialRepository implements CredentialRepositoryInterface
{
	/**
	 * Do we have stored credentials under the specified Credential ID?
	 *
	 * @param   string  $credentialId
	 *
	 * @return  bool
	 */
	public function has(string $credentialId): bool
	{
		$db    = Factory::getDbo();
		$query = $db->getQuery(true)
			->select('COUNT(*)')
			->from($db->qn('#__webauthn_credentials'))
			->where($db->qn('id') . ' = ' . $db->q($credentialId));

		try
		{
			$count = $db->setQuery($query)->loadResult();

			return $count > 0;
		}
		catch (Exception $e)
		{
			return false;
		}
	}

	/**
	 * Retrieve the attested credential data given a Credential ID
	 *
	 * @param   string  $credentialId
	 *
	 * @return  AttestedCredentialData
	 */
	public function get(string $credentialId): AttestedCredentialData
	{
		$db    = Factory::getDbo();
		$query = $db->getQuery(true)
			->select($db->qn('credential'))
			->from($db->qn('#__webauthn_credentials'))
			->where($db->qn('id') . ' = ' . $db->q($credentialId));

		$json = $db->setQuery($query)->loadResult();

		if (empty($json))
		{
			throw new RuntimeException(Text::_('PLG_SYSTSEM_WEBAUTHN_ERR_NO_STORED_CREDENTIAL'));
		}

		$data = @json_decode($json, true);

		if (is_null($data))
		{
			throw new RuntimeException(Text::_('PLG_SYSTSEM_WEBAUTHN_ERR_CORRUPT_STORED_CREDENTIAL'));
		}

		return new AttestedCredentialData($data['aaguid'], $credentialId, $data['credentialPublicKey']);
	}

	/**
	 * Get all credentials for a given user ID
	 *
	 * @param   int  $user_id  The user ID
	 *
	 * @return  array
	 */
	public function getAll(int $user_id): array
	{
		$db    = Factory::getDbo();
		$query = $db->getQuery(true)
			->select('*')
			->from($db->qn('#__webauthn_credentials'))
			->where($db->qn('user_id') . ' = ' . $db->q($user_id));

		try
		{
			$results = $db->setQuery($query)->loadAssocList();
		}
		catch (Exception $e)
		{
			return [];
		}

		if (empty($results))
		{
			return [];
		}

		return $results;
	}

	/**
	 * Add or update an attested credential for a given user. If another user is using the same credential ID the
	 * process will fail.
	 *
	 * @param   AttestedCredentialData  $credentialData  The attested credential data to store
	 * @param   string|null             $label           The human readable label to attach
	 * @param   User|null               $user            The user to store it for
	 *
	 * @return  void
	 */
	public function set(AttestedCredentialData $credentialData, string $label = '', User $user = null): void
	{
		if (empty($user))
		{
			$user = Factory::getUser();
		}

		if ($user->guest)
		{
			throw new RuntimeException(Text::_('PLG_SYSTSEM_WEBAUTHN_ERR_CANT_STORE_FOR_GUEST'));
		}

		$update = false;

		if ($this->has($credentialData->getCredentialId()))
		{
			$secret      = Factory::getConfig()->get('secret', '');
			$data        = sprintf('%010u', $user->id);
			$myHandle    = hash_hmac('sha512', $data, $secret, true);
			$otherHandle = $this->getUserHandleFor($credentialData->getCredentialId());

			if ($otherHandle != $myHandle)
			{
				throw new RuntimeException(Text::_('PLG_SYSTSEM_WEBAUTHN_ERR_CREDENTIAL_ID_ALREADY_IN_USE'));
			}

			$update = true;
		}

		if (empty($label))
		{
			$label = $credentialData->getCredentialId();
		}

		$json = $credentialData->jsonSerialize();

		$o = (object) [
			'id'         => $credentialData->getCredentialId(),
			'user_id'    => $user->id,
			'label'      => $label,
			'credential' => $json,
		];

		$db = Factory::getDbo();

		if ($update)
		{
			$db->updateObject('#__webauthn_credentials', $o, ['id']);

			return;
		}

		$db->insertObject('#__webauthn_credentials', $o);
	}

	/**
	 * Update the human readable label of a credential
	 *
	 * @param   string  $credentialId  The credential ID
	 * @param   string  $label         The human readable label to set
	 *
	 * @return  void
	 */
	public function setLabel(string $credentialId, string $label): void
	{
		$db = Factory::getDbo();
		$o  = (object) [
			'id'      => $credentialId,
			'label'   => $label,
		];

		$db->updateObject('#__webauthn_credentials', $o, ['id'], false);
	}

	/**
	 * Remove stored credentials
	 *
	 * @param   string  $credentialId  The credentials ID to remove
	 *
	 * @return  void
	 */
	public function remove(string $credentialId): void
	{
		if (!$this->has($credentialId))
		{
			return;
		}

		$db    = Factory::getDbo();
		$query = $db->getQuery(true)
			->delete($db->qn('#__webauthn_credentials'))
			->where($db->qn('id') . ' = ' . $db->q($credentialId));

		$db->setQuery($query)->execute();
	}

	/**
	 * Return the user handle for the stored credential given its ID.
	 *
	 * The user handle must not be personally identifiable. Per https://w3c.github.io/webauthn/#user-handle it is
	 * acceptable to have a salted hash with a salt private to our server, e.g. Joomla's secret. The only immutable
	 * information in Joomla is the user ID so that's what we will be using.
	 *
	 * @param   string  $credentialId
	 *
	 * @return  string
	 */
	public function getUserHandleFor(string $credentialId): string
	{
		$db    = Factory::getDbo();
		$query = $db->getQuery(true)
			->select([
				$db->qn('user_id'),
			])
			->from($db->qn('#__webauthn_credentials'))
			->where($db->qn('id') . ' = ' . $db->q($credentialId));

		$user_id = $db->setQuery($query)->loadResult();

		if (empty($user_id))
		{
			throw new RuntimeException(Text::_('PLG_SYSTSEM_WEBAUTHN_ERR_NO_STORED_CREDENTIAL'));
		}

		$user = Factory::getUser($user_id);

		if ($user->id != $user_id)
		{
			throw new RuntimeException(Text::sprintf('PLG_SYSTSEM_WEBAUTHN_ERR_USER_REMOVED', $user_id));
		}

		$secret = Factory::getConfig()->get('secret', '');
		$data   = sprintf('%010u', $user->id);

		return hash_hmac('sha512', $data, $secret, true);
	}

	/**
	 * Returns the last seen counter for this authenticator
	 *
	 * @param   string   $credentialId  The authenticator's credential ID
	 *
	 * @return  int
	 */
	public function getCounterFor(string $credentialId): int
	{
		$db    = Factory::getDbo();
		$query = $db->getQuery(true)
			->select([
				$db->qn('counter'),
			])
			->from($db->qn('#__webauthn_credentials'))
			->where($db->qn('id') . ' = ' . $db->q($credentialId));

		$counter = $db->setQuery($query)->loadResult();

		if (is_null($counter))
		{
			throw new RuntimeException(Text::_('PLG_SYSTSEM_WEBAUTHN_ERR_NO_STORED_CREDENTIAL'));
		}

		return (int) $counter;
	}

	/**
	 * Update the stored counter for this authenticator
	 *
	 * @param   string  $credentialId  The authenticator's credential ID
	 * @param   int     $newCounter    The new value of the counter we should store in the database
	 */
	public function updateCounterFor(string $credentialId, int $newCounter): void
	{
		$db = Factory::getDbo();
		$o  = (object) [
			'id'      => $credentialId,
			'counter' => $newCounter,
		];

		$db->updateObject('#__webauthn_credentials', $o, ['id'], false);
	}

}