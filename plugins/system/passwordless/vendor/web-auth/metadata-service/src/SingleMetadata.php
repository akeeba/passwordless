<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Akeeba\Passwordless\Webauthn\MetadataService;

use function Akeeba\Passwordless\Safe\base64_decode;
use function Akeeba\Passwordless\Safe\json_decode;

class SingleMetadata
{
    /**
     * @var MetadataStatement
     */
    private $statement;
    /**
     * @var string
     */
    private $data;
    /**
     * @var bool
     */
    private $isBase64Encoded;

    public function __construct(string $data, bool $isBase64Encoded)
    {
        $this->data = $data;
        $this->isBase64Encoded = $isBase64Encoded;
    }

    public function getMetadataStatement(): \Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement
    {
        if (null === $this->statement) {
            $json = $this->data;
            if ($this->isBase64Encoded) {
                $json = \Akeeba\Passwordless\Safe\base64_decode($this->data, true);
            }
            $statement = \Akeeba\Passwordless\Safe\json_decode($json, true);
            $this->statement = \Akeeba\Passwordless\Webauthn\MetadataService\MetadataStatement::createFromArray($statement);
        }

        return $this->statement;
    }
}
