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

use Psr\Http\Message\ServerRequestInterface;

final class IgnoreTokenBindingHandler implements \Akeeba\Passwordless\Webauthn\TokenBinding\TokenBindingHandler
{
    public function check(\Akeeba\Passwordless\Webauthn\TokenBinding\TokenBinding $tokenBinding, ServerRequestInterface $request): void
    {
        //Does nothing
    }
}
