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

namespace Akeeba\Passwordless\Webauthn\AttestationStatement;

use function array_key_exists;
use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use JsonSerializable;
use function Akeeba\Passwordless\Safe\sprintf;
use Akeeba\Passwordless\Webauthn\TrustPath\TrustPath;
use Akeeba\Passwordless\Webauthn\TrustPath\TrustPathLoader;

class AttestationStatement implements JsonSerializable
{
    public const TYPE_NONE = 'none';
    public const TYPE_BASIC = 'basic';
    public const TYPE_SELF = 'self';
    public const TYPE_ATTCA = 'attca';
    public const TYPE_ECDAA = 'ecdaa';
    public const TYPE_ANONCA = 'anonca';

    /**
     * @var string
     */
    private $fmt;

    /**
     * @var mixed[]
     */
    private $attStmt;

    /**
     * @var TrustPath
     */
    private $trustPath;

    /**
     * @var string
     */
    private $type;

    /**
     * @param mixed[] $attStmt
     */
    public function __construct(string $fmt, array $attStmt, string $type, \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath $trustPath)
    {
        $this->fmt = $fmt;
        $this->attStmt = $attStmt;
        $this->type = $type;
        $this->trustPath = $trustPath;
    }

    /**
     * @param mixed[] $attStmt
     */
    public static function createNone(string $fmt, array $attStmt, \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath $trustPath): self
    {
        return new self($fmt, $attStmt, self::TYPE_NONE, $trustPath);
    }

    /**
     * @param mixed[] $attStmt
     */
    public static function createBasic(string $fmt, array $attStmt, \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath $trustPath): self
    {
        return new self($fmt, $attStmt, self::TYPE_BASIC, $trustPath);
    }

    /**
     * @param mixed[] $attStmt
     */
    public static function createSelf(string $fmt, array $attStmt, \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath $trustPath): self
    {
        return new self($fmt, $attStmt, self::TYPE_SELF, $trustPath);
    }

    /**
     * @param mixed[] $attStmt
     */
    public static function createAttCA(string $fmt, array $attStmt, \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath $trustPath): self
    {
        return new self($fmt, $attStmt, self::TYPE_ATTCA, $trustPath);
    }

    /**
     * @param mixed[] $attStmt
     */
    public static function createEcdaa(string $fmt, array $attStmt, \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath $trustPath): self
    {
        return new self($fmt, $attStmt, self::TYPE_ECDAA, $trustPath);
    }

    public static function createAnonymizationCA(string $fmt, array $attStmt, \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath $trustPath): self
    {
        return new self($fmt, $attStmt, self::TYPE_ANONCA, $trustPath);
    }

    public function getFmt(): string
    {
        return $this->fmt;
    }

    /**
     * @return mixed[]
     */
    public function getAttStmt(): array
    {
        return $this->attStmt;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->attStmt);
    }

    /**
     * @return mixed
     */
    public function get(string $key)
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true($this->has($key), \Akeeba\Passwordless\Safe\sprintf('The attestation statement has no key "%s".', $key));

        return $this->attStmt[$key];
    }

    public function getTrustPath(): \Akeeba\Passwordless\Webauthn\TrustPath\TrustPath
    {
        return $this->trustPath;
    }

    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @param mixed[] $data
     */
    public static function createFromArray(array $data): self
    {
        foreach (['fmt', 'attStmt', 'trustPath', 'type'] as $key) {
            \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::keyExists($data, $key, \Akeeba\Passwordless\Safe\sprintf('The key "%s" is missing', $key));
        }

        return new self(
            $data['fmt'],
            $data['attStmt'],
            $data['type'],
            \Akeeba\Passwordless\Webauthn\TrustPath\TrustPathLoader::loadTrustPath($data['trustPath'])
        );
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        return [
            'fmt' => $this->fmt,
            'attStmt' => $this->attStmt,
            'trustPath' => $this->trustPath->jsonSerialize(),
            'type' => $this->type,
        ];
    }
}
