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

use Akeeba\Passwordless\FG\ASN1\Universal\NullObject;
use Akeeba\Passwordless\FG\ASN1\Composite\AttributeTypeAndValue;

class AlgorithmIdentifier extends \Akeeba\Passwordless\FG\ASN1\Composite\AttributeTypeAndValue
{
    public function __construct($objectIdentifierString)
    {
        parent::__construct($objectIdentifierString, new \Akeeba\Passwordless\FG\ASN1\Universal\NullObject());
    }
}
