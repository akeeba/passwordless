<?php
/*
 * This file is part of the PHPASN1 library.
 *
 * Copyright © Friedrich Große <friedrich.grosse@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Akeeba\Passwordless\FG\ASN1\Universal;

use Akeeba\Passwordless\FG\ASN1\Construct;
use Akeeba\Passwordless\FG\ASN1\Parsable;
use Akeeba\Passwordless\FG\ASN1\Identifier;

class Sequence extends \Akeeba\Passwordless\FG\ASN1\Construct implements \Akeeba\Passwordless\FG\ASN1\Parsable
{
    public function getType()
    {
        return \Akeeba\Passwordless\FG\ASN1\Identifier::SEQUENCE;
    }
}
