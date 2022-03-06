<?php
/*
 * This file is part of the PHPASN1 library.
 *
 * Copyright © Friedrich Große <friedrich.grosse@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Akeeba\Passwordless\FG\ASN1\Composite;

use Akeeba\Passwordless\FG\ASN1\Universal\PrintableString;
use Akeeba\Passwordless\FG\ASN1\Universal\IA5String;
use Akeeba\Passwordless\FG\ASN1\Universal\UTF8String;

class RDNString extends \Akeeba\Passwordless\FG\ASN1\Composite\RelativeDistinguishedName
{
    /**
     * @param string|\FG\ASN1\Universal\ObjectIdentifier $objectIdentifierString
     * @param string|\FG\ASN1\ASNObject $value
     */
    public function __construct($objectIdentifierString, $value)
    {
        if (\Akeeba\Passwordless\FG\ASN1\Universal\PrintableString::isValid($value)) {
            $value = new \Akeeba\Passwordless\FG\ASN1\Universal\PrintableString($value);
        } else {
            if (\Akeeba\Passwordless\FG\ASN1\Universal\IA5String::isValid($value)) {
                $value = new \Akeeba\Passwordless\FG\ASN1\Universal\IA5String($value);
            } else {
                $value = new \Akeeba\Passwordless\FG\ASN1\Universal\UTF8String($value);
            }
        }

        parent::__construct($objectIdentifierString, $value);
    }
}
