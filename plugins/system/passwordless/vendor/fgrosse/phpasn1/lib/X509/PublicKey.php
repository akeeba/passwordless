<?php
/*
 * This file is part of the PHPASN1 library.
 *
 * Copyright © Friedrich Große <friedrich.grosse@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Akeeba\Passwordless\FG\X509;

use Akeeba\Passwordless\FG\ASN1\OID;
use Akeeba\Passwordless\FG\ASN1\Universal\NullObject;
use Akeeba\Passwordless\FG\ASN1\Universal\Sequence;
use Akeeba\Passwordless\FG\ASN1\Universal\BitString;
use Akeeba\Passwordless\FG\ASN1\Universal\ObjectIdentifier;

class PublicKey extends \Akeeba\Passwordless\FG\ASN1\Universal\Sequence
{
    /**
     * @param string $hexKey
     * @param \FG\ASN1\ASNObject|string $algorithmIdentifierString
     */
    public function __construct($hexKey, $algorithmIdentifierString = \Akeeba\Passwordless\FG\ASN1\OID::RSA_ENCRYPTION)
    {
        parent::__construct(
            new \Akeeba\Passwordless\FG\ASN1\Universal\Sequence(
                new \Akeeba\Passwordless\FG\ASN1\Universal\ObjectIdentifier($algorithmIdentifierString),
                new \Akeeba\Passwordless\FG\ASN1\Universal\NullObject()
            ),
            new \Akeeba\Passwordless\FG\ASN1\Universal\BitString($hexKey)
        );
    }
}
