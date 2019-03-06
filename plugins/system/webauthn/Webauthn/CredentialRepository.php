<?php
/**
 * @package   AkeebaSocialLogin
 * @copyright Copyright (c)2016-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\SocialLogin\Webauthn;

use Exception;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\User\User;
use RuntimeException;
use Webauthn\AttestedCredentialData;
use Webauthn\CredentialRepository as CredentialRepositoryInterface;

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
			->select('credential')
			->from($db->qn('#__webauthn_credentials'))
			->where($db->qn('id') . ' = ' . $db->q($credentialId));

		$json = $db->setQuery($query)->loadResult();

		if (empty($json))
		{
			throw new RuntimeException(Text::_('PLG_SOCIALLOGIN_WEBAUTHN_ERR_NO_STORED_CREDENTIAL'));
		}

		$data = @json_decode($json, true);

		if (is_null($data))
		{
			throw new RuntimeException(Text::_('PLG_SOCIALLOGIN_WEBAUTHN_ERR_CORRUPT_STORED_CREDENTIAL'));
		}

		return new AttestedCredentialData($data['aaguid'], $credentialId, $data['credentialPublicKey']);
	}

	/**
	 * Add or update an attested credential for a given user. If another user is using the same credential ID the
	 * process will fail.
	 *
	 * @param   AttestedCredentialData  $credentialData  The attested credential data to store
	 * @param   User|null               $user            The user to store it for
	 *
	 * @return  void
	 */
	public function set(AttestedCredentialData $credentialData, User $user = null): void
	{
		if (empty($user))
		{
			$user = Factory::getUser();
		}

		if ($user->guest)
		{
			throw new RuntimeException(Text::_('PLG_SOCIALLOGIN_WEBAUTHN_ERR_CANT_STORE_FOR_GUEST'));
		}

		$update = false;

		if ($this->has($credentialData->getCredentialId()))
		{
			$otherUsername = $this->getUserHandleFor($credentialData->getCredentialId());

			if ($otherUsername != $user->username)
			{
				throw new RuntimeException(Text::_('PLG_SOCIALLOGIN_WEBAUTHN_ERR_CREDENTIAL_ID_ALREADY_IN_USE'));
			}

			$update = true;
		}

		$json = $credentialData->jsonSerialize();

		$o = (object) [
			'id'         => $credentialData->getCredentialId(),
			'user_id'    => $user->id,
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
	 * Return the username for the stored credential given its ID
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
			throw new RuntimeException(Text::_('PLG_SOCIALLOGIN_WEBAUTHN_ERR_NO_STORED_CREDENTIAL'));
		}

		$user = Factory::getUser($user_id);

		if ($user->id != $user_id)
		{
			throw new RuntimeException(Text::sprintf('PLG_SOCIALLOGIN_WEBAUTHN_ERR_USER_REMOVED', $user_id));
		}

		return $user->username;
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
			throw new RuntimeException(Text::_('PLG_SOCIALLOGIN_WEBAUTHN_ERR_NO_STORED_CREDENTIAL'));
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