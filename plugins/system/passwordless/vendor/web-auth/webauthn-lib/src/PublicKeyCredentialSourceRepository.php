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

interface PublicKeyCredentialSourceRepository
{
    public function findOneByCredentialId(string $publicKeyCredentialId): ?\Akeeba\Passwordless\Webauthn\PublicKeyCredentialSource;

    /**
     * @return PublicKeyCredentialSource[]
     */
    public function findAllForUserEntity(\Akeeba\Passwordless\Webauthn\PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array;

    public function saveCredentialSource(\Akeeba\Passwordless\Webauthn\PublicKeyCredentialSource $publicKeyCredentialSource): void;
}
