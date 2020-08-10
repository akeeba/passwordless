<?php
/*
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2020 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Passwordless;

use Exception;
use FOFEncryptAes;
use InvalidArgumentException;
use Joomla\CMS\Encrypt\Aes as JoomlaAes;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Akeeba\Passwordless\Helper\Joomla;
use JsonException;
use RuntimeException;
use Throwable;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

// Protect from unauthorized access
defined('_JEXEC') or die();

/**
 * Handles the storage of WebAuthn credentials in the database
 *
 * @since   1.0.0
 */
class CredentialRepository implements PublicKeyCredentialSourceRepository
{
	/**
	 * Returns a PublicKeyCredentialSource object given the public key credential ID
	 *
	 * @param string $publicKeyCredentialId
	 *
	 * @return  PublicKeyCredentialSource|null
	 *
	 * @since   1.0.0
	 */
	public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
	{
		$db           = Joomla::getDbo();
		$credentialId = base64_encode($publicKeyCredentialId);
		$query        = $db->getQuery(true)
			->select($db->qn('credential'))
			->from($db->qn('#__passwordless_credentials'))
			->where($db->qn('id') . ' = ' . $db->q($credentialId));

		$encrypted = $db->setQuery($query)->loadResult();

		if (empty($encrypted))
		{
			return null;
		}

		$json = $this->decryptCredential($encrypted);

		try
		{
			return PublicKeyCredentialSource::createFromArray(json_decode($json, true));
		}
		catch (Throwable $e)
		{
			return null;
		}
	}

	/**
	 * Returns all PublicKeyCredentialSource objects given a user entity. We only use the `id` property of the user
	 * entity, cast to integer, as the Joomla user ID by which records are keyed in the database table.
	 *
	 * @return PublicKeyCredentialSource[]
	 *
	 * @since  1.0.0
	 */
	public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
	{
		$db         = Joomla::getDbo();
		$userHandle = $publicKeyCredentialUserEntity->getId();
		$query      = $db->getQuery(true)
			->select('*')
			->from($db->qn('#__passwordless_credentials'))
			->where($db->qn('user_id') . ' = ' . $db->q($userHandle));

		try
		{
			$records = $db->setQuery($query)->loadAssocList();
		}
		catch (Exception $e)
		{
			return [];
		}

		$records = array_map(function ($record) {
			try
			{
				$json = $this->decryptCredential($record['credential']);
				$data = json_decode($json, true);
			}
			catch (JsonException $e)
			{
				return null;
			}

			if (empty($data))
			{
				return null;
			}

			try
			{
				return PublicKeyCredentialSource::createFromArray($data);
			}
			catch (InvalidArgumentException $e)
			{
				return null;
			}
		}, $records);

		return array_filter($records, function ($record) {
			return !is_null($record) && is_object($record) && ($record instanceof PublicKeyCredentialSource);
		});
	}

	/**
	 * Add or update an attested credential for a given user.
	 *
	 * @param PublicKeyCredentialSource $publicKeyCredentialSource The public key credential source to store
	 *
	 * @return  void
	 *
	 * @since   1.0.0
	 */
	public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
	{
		// Default values for saving a new credential source
		$credentialId = base64_encode($publicKeyCredentialSource->getPublicKeyCredentialId());
		$user         = Joomla::getUser();
		$o            = (object) [
			'id'         => $credentialId,
			'user_id'    => $this->getHandleFromUserId($user->id),
			'label'      => Text::sprintf('PLG_SYSTEM_PASSWORDLESS_LBL_DEFAULT_AUTHENTICATOR_LABEL', Joomla::formatDate('now')),
			'credential' => json_encode($publicKeyCredentialSource),
		];
		$update       = false;
		$db           = Joomla::getDbo();

		// Try to find an existing record
		try
		{
			$query     = $db->getQuery(true)
				->select('*')
				->from($db->qn('#__passwordless_credentials'))
				->where($db->qn('id') . ' = ' . $db->q($credentialId));
			$oldRecord = $db->setQuery($query)->loadObject();

			if (is_null($oldRecord))
			{
				throw new Exception('This is a new record');
			}

			/**
			 * Sanity check. The existing credential source must have the same user handle as the one I am trying to
			 * save. Otherwise something fishy is going on.
			 */
			if ($oldRecord->user_id != $publicKeyCredentialSource->getUserHandle())
			{
				throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CREDENTIAL_ID_ALREADY_IN_USE'));
			}

			$o->user_id = $oldRecord->user_id;
			$o->label   = $oldRecord->label;
			$update     = true;
		}
		catch (Exception $e)
		{
		}

		$o->credential = $this->encryptCredential($o->credential);

		if ($update)
		{
			$db->updateObject('#__passwordless_credentials', $o, ['id']);

			return;
		}

		/**
		 * This check is deliberately skipped for updates. When logging in the underlying library will try to save the
		 * credential source. This is necessary to update the last known authenticator signature counter which prevents
		 * replay attacks. When we are saving a new record, though, we have to make sure we are not a guest user. Hence
		 * the check below.
		 */
		if ((is_null($user) || $user->guest))
		{
			throw new RuntimeException(Text::_('PLG_SYSTEM_PASSWORDLESS_ERR_CANT_STORE_FOR_GUEST'));
		}

		$db->insertObject('#__passwordless_credentials', $o);
	}

	/**
	 * Get all credential information for a given user ID. This is meant to only be used for displaying records.
	 *
	 * @param int $user_id The user ID
	 *
	 * @return  array
	 *
	 * @since   1.0.0
	 */
	public function getAll(int $user_id): array
	{

		$db         = Joomla::getDbo();
		$userHandle = $this->getHandleFromUserId($user_id);
		$query      = $db->getQuery(true)
			->select('*')
			->from($db->qn('#__passwordless_credentials'))
			->where($db->qn('user_id') . ' = ' . $db->q($userHandle));

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
	 * Do we have stored credentials under the specified Credential ID?
	 *
	 * @param string $credentialId
	 *
	 * @return  bool
	 *
	 * @since   1.0.0
	 */
	public function has(string $credentialId): bool
	{
		$db           = Joomla::getDbo();
		$credentialId = base64_encode($credentialId);
		$query        = $db->getQuery(true)
			->select('COUNT(*)')
			->from($db->qn('#__passwordless_credentials'))
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
	 * Update the human readable label of a credential
	 *
	 * @param string $credentialId The credential ID
	 * @param string $label        The human readable label to set
	 *
	 * @return  void
	 *
	 * @since   1.0.0
	 */
	public function setLabel(string $credentialId, string $label): void
	{
		$db           = Joomla::getDbo();
		$credentialId = base64_encode($credentialId);
		$o            = (object) [
			'id'    => $credentialId,
			'label' => $label,
		];

		$db->updateObject('#__passwordless_credentials', $o, ['id'], false);
	}

	/**
	 * Remove stored credentials
	 *
	 * @param string $credentialId The credentials ID to remove
	 *
	 * @return  void
	 *
	 * @since   1.0.0
	 */
	public function remove(string $credentialId): void
	{
		if (!$this->has($credentialId))
		{
			return;
		}

		$db           = Joomla::getDbo();
		$credentialId = base64_encode($credentialId);
		$query        = $db->getQuery(true)
			->delete($db->qn('#__passwordless_credentials'))
			->where($db->qn('id') . ' = ' . $db->q($credentialId));

		$db->setQuery($query)->execute();
	}

	/**
	 * Return the user handle for the stored credential given its ID.
	 *
	 * The user handle must not be personally identifiable. Per https://w3c.github.io/passwordless/#user-handle it is
	 * acceptable to have a salted hash with a salt private to our server, e.g. Joomla's secret. The only immutable
	 * information in Joomla is the user ID so that's what we will be using.
	 *
	 * @param string $credentialId
	 *
	 * @return  string
	 *
	 * @since   1.0.0
	 */
	public function getUserHandleFor(string $credentialId): string
	{
		$publicKeyCredentialSource = $this->findOneByCredentialId($credentialId);

		if (empty($publicKeyCredentialSource))
		{
			return '';
		}

		return $publicKeyCredentialSource->getUserHandle();
	}

	/**
	 * Return a user handle given an integer Joomla user ID. We use the HMAC-SHA-256 of the user ID with the site's
	 * secret as the key. Using it instead of SHA-512 is on purpose! WebAuthn only allows user handles up to 64 bytes
	 * long.
	 *
	 * @param int $id The user ID to convert
	 *
	 * @return  string  The user handle (HMAC-SHA-256 of the user ID)
	 *
	 * @since   1.0.0
	 */
	public function getHandleFromUserId(int $id): string
	{
		$key  = $this->getEncryptionKey();
		$data = sprintf('%010u', $id);

		return hash_hmac('sha256', $data, $key, false);
	}

	/**
	 * Get the user ID from the user handle
	 *
	 * This is a VERY inefficient method. Since the user handle is an HMAC-SHA-256 of the user ID we can't just go
	 * directly from a handle back to an ID. We have to iterate all user IDs, calculate their handles and compare them
	 * to the given handle.
	 *
	 * To prevent a lengthy infinite loop in case of an invalid user handle we don't iterate the entire 2+ billion valid
	 * 32-bit integer range. We load the user IDs of active users (not blocked, not pending activation) and iterate
	 * through them.
	 *
	 * To avoid memory outage on large sites with thousands of active user records we load up to 10000 users at a time.
	 * Each block of 10,000 user IDs takes about 60-80 msec to iterate. On a site with 200,000 active users this method
	 * will take less than 1.5 seconds. This is slow but not impractical, even on crowded shared hosts with a quarter of
	 * the performance of my test subject (a mid-range, shared hosting server).
	 *
	 * @param   string|null  $userHandle
	 *
	 * @return int|null
	 */
	public function getUserIdFromHandle(?string $userHandle): ?int
	{
		if (empty($userHandle))
		{
			return null;
		}

		$db    = Joomla::getDbo();

		// Check that the userHandle does exist in the database
		$query = $db->getQuery(true)
			->select('COUNT(*)')
			->from($db->qn('#__passwordless_credentials'))
			->where($db->qn('user_id') . ' = ' . $db->q($userHandle));

		try
		{
			$numRecords = $db->setQuery($query)->loadResult();
		}
		catch (Exception $e)
		{
			return null;
		}

		if (is_null($numRecords) || ($numRecords < 1))
		{
			return null;
		}

		// Prepare the query
		$query = $db->getQuery(true)
			->select([$db->qn('id')])
			->from($db->qn('#__users'))
			->where($db->qn('block') . ' = 0')
			->where(
				'(' .
				$db->qn('activation') . ' IS NULL OR ' .
				$db->qn('activation') . ' = 0 OR ' .
				$db->qn('activation') . ' = ' . $db->q('') .
				')'
			);

		$key   = $this->getEncryptionKey();
		$start = 0;
		$limit = 10000;

		while (true)
		{
			try
			{
				$ids = $db->setQuery($query, $start, $limit)->loadColumn();
			}
			catch (Exception $e)
			{
				return null;
			}

			if (empty($ids))
			{
				return null;
			}

			foreach ($ids as $userId)
			{
				$data       = sprintf('%010u', $userId);
				$thisHandle = hash_hmac('sha256', $data, $key, false);

				if ($thisHandle == $userHandle)
				{
					return $userId;
				}
			}

			$start += $limit;
		}
	}

	/**
	 * Encrypt the credential source before saving it to the database
	 *
	 * @param string $credential The unencrypted, JSON-encoded credential source
	 *
	 * @return  string  The encrypted credential source, base64 encoded
	 *
	 * @since   1.0.0
	 */
	private function encryptCredential(string $credential): string
	{
		$key = $this->getEncryptionKey();

		if (empty($key))
		{
			return $credential;
		}

		if (version_compare(JVERSION, '3.999.999', 'le'))
		{
			$aes = new FOFEncryptAes($key, 256);
		}
		else
		{
			$aes = new JoomlaAes($key, 256);
		}

		return trim($aes->encryptString($credential));
	}

	/**
	 * Decrypt the credential source if it was already encrypted in the database
	 *
	 * @param string $credential The encrypted credential source, base64 encoded
	 *
	 * @return  string  The decrypted, JSON-encoded credential source
	 *
	 * @since   1.0.0
	 */
	private function decryptCredential(string $credential): string
	{
		$key = $this->getEncryptionKey();

		if (empty($key))
		{
			return $credential;
		}

		// Was the credential stored unencrypted (e.g. the site's secret was empty)?
		if ((strpos($credential, '{') !== false) && (strpos($credential, '"publicKeyCredentialId"') !== false))
		{
			return $credential;
		}

		if (version_compare(JVERSION, '3.999.999', 'le'))
		{
			$aes = new FOFEncryptAes($key, 256);
		}
		else
		{
			$aes = new JoomlaAes($key, 256);
		}

		return trim($aes->decryptString($credential));
	}

	/**
	 * Get the site's secret, used as an encryption key
	 *
	 * @return  string
	 *
	 * @since   1.0.0
	 */
	private function getEncryptionKey(): string
	{
		try
		{
			$secret = Joomla::getConfig()->get('secret', '');
		}
		catch (Exception $e)
		{
			$secret = '';
		}

		return $secret;
	}
}
