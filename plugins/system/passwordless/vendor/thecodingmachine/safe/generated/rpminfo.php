<?php

namespace Akeeba\Passwordless\Safe;

use Akeeba\Passwordless\Safe\Exceptions\RpminfoException;

/**
 * Add an additional retrieved tag in subsequent queries.
 *
 * @param int $tag One of RPMTAG_* constant, see the rpminfo constants page.
 * @throws RpminfoException
 *
 */
function rpmaddtag(int $tag): void
{
    error_clear_last();
    $result = \rpmaddtag($tag);
    if ($result === false) {
        throw \Akeeba\Passwordless\Safe\Exceptions\RpminfoException::createFromPhpError();
    }
}
