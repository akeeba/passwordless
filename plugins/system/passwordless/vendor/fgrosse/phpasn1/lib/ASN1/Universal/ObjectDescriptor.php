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

use Akeeba\Passwordless\FG\ASN1\Identifier;

class ObjectDescriptor extends \Akeeba\Passwordless\FG\ASN1\Universal\GraphicString
{
    public function __construct($objectDescription)
    {
        parent::__construct($objectDescription);
    }

    public function getType()
    {
        return \Akeeba\Passwordless\FG\ASN1\Identifier::OBJECT_DESCRIPTOR;
    }
}
