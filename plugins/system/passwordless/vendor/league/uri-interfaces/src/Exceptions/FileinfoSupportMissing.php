<?php

/**
 * League.Uri (https://uri.thephpleague.com)
 *
 * (c) Ignace Nyamagana Butera <nyamsprod@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Akeeba\Passwordless\League\Uri\Exceptions;

use Akeeba\Passwordless\League\Uri\Contracts\UriException;

class FileinfoSupportMissing extends \RuntimeException implements \Akeeba\Passwordless\League\Uri\Contracts\UriException
{
}
