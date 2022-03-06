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

use function array_key_exists;
use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use function Akeeba\Passwordless\Safe\sprintf;

class PatternAccuracyDescriptor extends \Akeeba\Passwordless\Webauthn\MetadataService\AbstractDescriptor
{
    /**
     * @var int
     */
    private $minComplexity;

    public function __construct(int $minComplexity, ?int $maxRetries = null, ?int $blockSlowdown = null)
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::greaterOrEqualThan($minComplexity, 0, \Akeeba\Passwordless\Webauthn\MetadataService\Utils::logicException('Invalid data. The value of "minComplexity" must be a positive integer'));
        $this->minComplexity = $minComplexity;
        parent::__construct($maxRetries, $blockSlowdown);
    }

    public function getMinComplexity(): int
    {
        return $this->minComplexity;
    }

    public static function createFromArray(array $data): self
    {
        $data = \Akeeba\Passwordless\Webauthn\MetadataService\Utils::filterNullValues($data);
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($data, 'minComplexity', \Akeeba\Passwordless\Webauthn\MetadataService\Utils::logicException('The key "minComplexity" is missing'));
        foreach (['minComplexity', 'maxRetries', 'blockSlowdown'] as $key) {
            if (array_key_exists($key, $data)) {
                \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::integer($data[$key], \Akeeba\Passwordless\Webauthn\MetadataService\Utils::logicException(\Akeeba\Passwordless\Safe\sprintf('Invalid data. The value of "%s" must be a positive integer', $key)));
            }
        }

        return new self(
            $data['minComplexity'],
        $data['maxRetries'] ?? null,
        $data['blockSlowdown'] ?? null
        );
    }

    public function jsonSerialize(): array
    {
        $data = [
            'minComplexity' => $this->minComplexity,
            'maxRetries' => $this->getMaxRetries(),
            'blockSlowdown' => $this->getBlockSlowdown(),
        ];

        return \Akeeba\Passwordless\Webauthn\MetadataService\Utils::filterNullValues($data);
    }
}
