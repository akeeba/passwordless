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

use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;

class CodeAccuracyDescriptor extends \Akeeba\Passwordless\Webauthn\MetadataService\AbstractDescriptor
{
    /**
     * @var int
     */
    private $base;

    /**
     * @var int
     */
    private $minLength;

    public function __construct(int $base, int $minLength, ?int $maxRetries = null, ?int $blockSlowdown = null)
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::greaterOrEqualThan($base, 0, \Akeeba\Passwordless\Webauthn\MetadataService\Utils::logicException('Invalid data. The value of "base" must be a positive integer'));
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::greaterOrEqualThan($minLength, 0, \Akeeba\Passwordless\Webauthn\MetadataService\Utils::logicException('Invalid data. The value of "minLength" must be a positive integer'));
        $this->base = $base;
        $this->minLength = $minLength;
        parent::__construct($maxRetries, $blockSlowdown);
    }

    public function getBase(): int
    {
        return $this->base;
    }

    public function getMinLength(): int
    {
        return $this->minLength;
    }

    public static function createFromArray(array $data): self
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($data, 'base', \Akeeba\Passwordless\Webauthn\MetadataService\Utils::logicException('The parameter "base" is missing'));
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($data, 'minLength', \Akeeba\Passwordless\Webauthn\MetadataService\Utils::logicException('The parameter "minLength" is missing'));

        return new self(
            $data['base'],
            $data['minLength'],
            $data['maxRetries'] ?? null,
            $data['blockSlowdown'] ?? null
        );
    }

    public function jsonSerialize(): array
    {
        $data = [
            'base' => $this->base,
            'minLength' => $this->minLength,
            'maxRetries' => $this->getMaxRetries(),
            'blockSlowdown' => $this->getBlockSlowdown(),
        ];

        return \Akeeba\Passwordless\Webauthn\MetadataService\Utils::filterNullValues($data);
    }
}
