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

use Akeeba\Passwordless\Assert\Assertion;
use Psr\Http\Message\ServerRequestInterface;

final class SecTokenBindingHandler implements \Akeeba\Passwordless\Webauthn\TokenBinding\TokenBindingHandler
{
    public function check(\Akeeba\Passwordless\Webauthn\TokenBinding\TokenBinding $tokenBinding, ServerRequestInterface $request): void
    {
        if (\Akeeba\Passwordless\Webauthn\TokenBinding\TokenBinding::TOKEN_BINDING_STATUS_PRESENT !== $tokenBinding->getStatus()) {
            return;
        }

        \Akeeba\Passwordless\Assert\Assertion::true($request->hasHeader('Sec-Token-Binding'), 'The header parameter "Sec-Token-Binding" is missing.');
        $tokenBindingIds = $request->getHeader('Sec-Token-Binding');
        \Akeeba\Passwordless\Assert\Assertion::count($tokenBindingIds, 1, 'The header parameter "Sec-Token-Binding" is invalid.');
        $tokenBindingId = reset($tokenBindingIds);
        \Akeeba\Passwordless\Assert\Assertion::eq($tokenBindingId, $tokenBinding->getId(), 'The header parameter "Sec-Token-Binding" is invalid.');
    }
}
