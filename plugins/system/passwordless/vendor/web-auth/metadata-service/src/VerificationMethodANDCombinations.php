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

use Akeeba\Passwordless\Assert\Assertion;
use JsonSerializable;

class VerificationMethodANDCombinations implements JsonSerializable
{
    /**
     * @var VerificationMethodDescriptor[]
     */
    private $verificationMethods = [];

    public function addVerificationMethodDescriptor(\Akeeba\Passwordless\Webauthn\MetadataService\VerificationMethodDescriptor $verificationMethodDescriptor): self
    {
        $this->verificationMethods[] = $verificationMethodDescriptor;

        return $this;
    }

    /**
     * @return VerificationMethodDescriptor[]
     */
    public function getVerificationMethods(): array
    {
        return $this->verificationMethods;
    }

    public static function createFromArray(array $data): self
    {
        $object = new self();

        foreach ($data as $datum) {
            \Akeeba\Passwordless\Assert\Assertion::isArray($datum, \Akeeba\Passwordless\Webauthn\MetadataService\Utils::logicException('Invalid data'));
            $object->addVerificationMethodDescriptor(\Akeeba\Passwordless\Webauthn\MetadataService\VerificationMethodDescriptor::createFromArray($datum));
        }

        return $object;
    }

    public function jsonSerialize(): array
    {
        return array_map(static function (\Akeeba\Passwordless\Webauthn\MetadataService\VerificationMethodDescriptor $object): array {
            return $object->jsonSerialize();
        }, $this->verificationMethods);
    }
}
