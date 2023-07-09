<?php
/**
 * @package         Joomla.Plugin
 * @subpackage      System.Webauthn
 *
 * @copyright   (C) 2022 Open Source Matters, Inc. <https://www.joomla.org>
 * @license         GNU General Public License version 2 or later; see LICENSE.txt
 */

namespace Akeeba\Plugin\System\Passwordless;

// Protect from unauthorized access
defined('_JEXEC') or die();

use Exception;
use Joomla\CMS\Date\Date;
use Joomla\CMS\Http\HttpFactory;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token\Plain;
use Webauthn\MetadataService\MetadataStatement;
use Webauthn\MetadataService\MetadataStatementRepository;
use function defined;

/**
 * Authenticator metadata repository.
 *
 * This repository contains the metadata of all FIDO authenticators as published by the FIDO
 * Alliance in their MDS version 3.0.
 *
 * @see   https://fidoalliance.org/metadata/
 * @since 2.0.0
 */
class MetadataRepository implements MetadataStatementRepository
{
	/**
	 * Cache of authenticator metadata statements
	 *
	 * @var   MetadataStatement[]
	 * @since 2.0.0
	 */
	private $mdsCache = [];

	/**
	 * Map of AAGUID to $mdsCache index
	 *
	 * @var   array
	 * @since 2.0.0
	 */
	private $mdsMap = [];

	/**
	 * Public constructor.
	 *
	 * @since 2.0.0
	 */
	public function __construct()
	{
		$this->load();
	}

	/**
	 * Find an authenticator metadata statement given an AAGUID
	 *
	 * @param   string  $aaguid  The AAGUID to find
	 *
	 * @return  MetadataStatement|null  The metadata statement; null if the AAGUID is unknown
	 * @since   2.0.0
	 */
	public function findOneByAAGUID(string $aaguid): ?MetadataStatement
	{
		$idx = $this->mdsMap[$aaguid] ?? null;

		return $idx ? $this->mdsCache[$idx] : null;
	}

	/**
	 * Get basic information of the known FIDO authenticators by AAGUID
	 *
	 * @return  object[]
	 * @since   2.0.0
	 */
	public function getKnownAuthenticators(): array
	{
		$mapKeys = function (MetadataStatement $meta)
		{
			return $meta->getAaguid();
		};
		$mapvalues = function (MetadataStatement $meta)
		{
			return $meta->getAaguid() ? (object) [
				'description' => $meta->getDescription(),
				'icon'        => $meta->getIcon(),
			] : null;
		};
		$keys    = array_map($mapKeys, $this->mdsCache);
		$values  = array_map($mapvalues, $this->mdsCache);
		$return  = array_combine($keys, $values) ?: [];

		$filter = function ($x)
		{
			return !empty($x);
		};

		return array_filter($return, $filter);
	}

	/**
	 * Load the authenticator metadata cache
	 *
	 * @param   bool  $force  Force reload from the web service
	 *
	 * @return  void
	 * @since   2.0.0
	 */
	private function load(bool $force = false): void
	{
		$this->mdsCache = [];
		$this->mdsMap   = [];
		$jwtFilename    = JPATH_PLUGINS . '/system/webauthn/fido.jwt';

		$rawJwt = file_get_contents($jwtFilename);

		if (!is_string($rawJwt) || strlen($rawJwt) < 1024)
		{
			return;
		}

		try
		{
			$jwtConfig = Configuration::forUnsecuredSigner();
			$token     = $jwtConfig->parser()->parse($rawJwt);
		}
		catch (Exception $e)
		{
			return;
		}

		if (!($token instanceof Plain))
		{
			return;
		}

		unset($rawJwt);

		$entriesMapper = function (object $entry)
		{
			try
			{
				$object = json_decode(json_encode($entry->metadataStatement), true);

				/**
				 * This prevents an error when we're asking for attestation on authenticators which
				 * don't allow it. We are really not interested in the attestation per se, but
				 * requiring an attestation is the only way we can get the AAGUID of the
				 * authenticator.
				 */
				if (isset($object->attestationTypes))
				{
					unset($object->attestationTypes);
				}

				return MetadataStatement::createFromArray((array) $object);
			}
			catch (Exception $e)
			{
				return null;
			}
		};
		$entries = array_map($entriesMapper, $token->claims()->get('entries', []));

		unset($token);

		$entriesFilter                = function ($x)
		{
			return !empty($x);
		};
		$this->mdsCache = array_filter($entries, $entriesFilter);

		foreach ($this->mdsCache as $idx => $meta)
		{
			$aaguid = $meta->getAaguid();

			if (empty($aaguid))
			{
				continue;
			}

			$this->mdsMap[$aaguid] = $idx;
		}
	}
}
