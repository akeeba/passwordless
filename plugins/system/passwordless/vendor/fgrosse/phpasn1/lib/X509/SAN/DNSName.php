<?php
/*
 * This file is part of the PHPASN1 library.
 *
 * Copyright © Friedrich Große <friedrich.grosse@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Akeeba\Passwordless\FG\X509\SAN;

use Akeeba\Passwordless\FG\ASN1\Universal\GeneralString;

class DNSName extends \Akeeba\Passwordless\FG\ASN1\Universal\GeneralString
{
    const IDENTIFIER = 0x82; // not sure yet why this is the identifier used in SAN extensions

    public function __construct($dnsNameString)
    {
        parent::__construct($dnsNameString);
    }

    public function getType()
    {
        return self::IDENTIFIER;
    }
}
