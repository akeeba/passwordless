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

use Akeeba\Passwordless\FG\ASN1\ASNObject;
use Akeeba\Passwordless\FG\ASN1\Universal\Sequence;
use Akeeba\Passwordless\FG\ASN1\Universal\ObjectIdentifier;

class AttributeTypeAndValue extends \Akeeba\Passwordless\FG\ASN1\Universal\Sequence
{
    /**
     * @param ObjectIdentifier|string $objIdentifier
     * @param \FG\ASN1\ASNObject $value
     */
    public function __construct($objIdentifier, \Akeeba\Passwordless\FG\ASN1\ASNObject $value)
    {
        if ($objIdentifier instanceof \Akeeba\Passwordless\FG\ASN1\Universal\ObjectIdentifier == false) {
            $objIdentifier = new \Akeeba\Passwordless\FG\ASN1\Universal\ObjectIdentifier($objIdentifier);
        }
        parent::__construct($objIdentifier, $value);
    }

    public function __toString()
    {
        return $this->children[0].': '.$this->children[1];
    }
}
