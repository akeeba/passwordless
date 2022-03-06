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

namespace Akeeba\Passwordless\Webauthn;

use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use JsonSerializable;
use function Akeeba\Passwordless\Safe\json_decode;

class PublicKeyCredentialParameters implements JsonSerializable
{
    /**
     * @var string
     */
    private $type;

    /**
     * @var int
     */
    private $alg;

    public function __construct(string $type, int $alg)
    {
        $this->type = $type;
        $this->alg = $alg;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getAlg(): int
    {
        return $this->alg;
    }

    public static function createFromString(string $data): self
    {
        $data = \Akeeba\Passwordless\Safe\json_decode($data, true);
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::isArray($data, 'Invalid data');

        return self::createFromArray($data);
    }

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): self
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($json, 'type', 'Invalid input. "type" is missing.');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::string($json['type'], 'Invalid input. "type" is not a string.');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($json, 'alg', 'Invalid input. "alg" is missing.');
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::integer($json['alg'], 'Invalid input. "alg" is not an integer.');

        return new self(
            $json['type'],
            $json['alg']
        );
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        return [
            'type' => $this->type,
            'alg' => $this->alg,
        ];
    }
}
