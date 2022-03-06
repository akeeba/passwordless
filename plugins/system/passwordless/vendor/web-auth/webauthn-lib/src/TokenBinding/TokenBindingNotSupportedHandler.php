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

namespace Akeeba\Passwordless\Webauthn\TokenBinding;

use Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion;
use Psr\Http\Message\ServerRequestInterface;

final class TokenBindingNotSupportedHandler implements \Akeeba\Passwordless\Webauthn\TokenBinding\TokenBindingHandler
{
    public function check(\Akeeba\Passwordless\Webauthn\TokenBinding\TokenBinding $tokenBinding, ServerRequestInterface $request): void
    {
        \Akeeba\Passwordless\Assert\Akeeba\Passwordless\Assertion::true(\Akeeba\Passwordless\Webauthn\TokenBinding\TokenBinding::TOKEN_BINDING_STATUS_PRESENT !== $tokenBinding->getStatus(), 'Token binding not supported.');
    }
}
