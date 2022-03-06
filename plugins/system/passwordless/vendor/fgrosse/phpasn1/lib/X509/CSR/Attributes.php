<?php
/*
 * This file is part of the PHPASN1 library.
 *
 * Copyright © Friedrich Große <friedrich.grosse@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Akeeba\Passwordless\FG\X509\CSR;

use Akeeba\Passwordless\FG\ASN1\ASNObject;
use Akeeba\Passwordless\FG\X509\CertificateExtensions;
use Akeeba\Passwordless\FG\ASN1\OID;
use Akeeba\Passwordless\FG\ASN1\Parsable;
use Akeeba\Passwordless\FG\ASN1\Construct;
use Akeeba\Passwordless\FG\ASN1\Identifier;
use Akeeba\Passwordless\FG\ASN1\Universal\Set;
use Akeeba\Passwordless\FG\ASN1\Universal\Sequence;
use Akeeba\Passwordless\FG\ASN1\Universal\ObjectIdentifier;

class Attributes extends \Akeeba\Passwordless\FG\ASN1\Construct implements \Akeeba\Passwordless\FG\ASN1\Parsable
{
    public function getType()
    {
        return 0xA0;
    }

    public function addAttribute($objectIdentifier, \Akeeba\Passwordless\FG\ASN1\Universal\Set $attribute)
    {
        if (is_string($objectIdentifier)) {
            $objectIdentifier = new \Akeeba\Passwordless\FG\ASN1\Universal\ObjectIdentifier($objectIdentifier);
        }
        $attributeSequence = new \Akeeba\Passwordless\FG\ASN1\Universal\Sequence($objectIdentifier, $attribute);
        $attributeSequence->getNumberOfLengthOctets();  // length and number of length octets is calculated
        $this->addChild($attributeSequence);
    }

    public static function fromBinary(&$binaryData, &$offsetIndex = 0)
    {
        self::parseIdentifier($binaryData[$offsetIndex], 0xA0, $offsetIndex++);
        $contentLength = self::parseContentLength($binaryData, $offsetIndex);
        $octetsToRead = $contentLength;

        $parsedObject = new self();
        while ($octetsToRead > 0) {
            $initialOffset = $offsetIndex; // used to calculate how much bits have been read
            self::parseIdentifier($binaryData[$offsetIndex], \Akeeba\Passwordless\FG\ASN1\Identifier::SEQUENCE, $offsetIndex++);
            self::parseContentLength($binaryData, $offsetIndex);

            $objectIdentifier = \Akeeba\Passwordless\FG\ASN1\Universal\ObjectIdentifier::fromBinary($binaryData, $offsetIndex);
            $oidString = $objectIdentifier->getContent();
            if ($oidString == \Akeeba\Passwordless\FG\ASN1\OID::PKCS9_EXTENSION_REQUEST) {
                $attribute = \Akeeba\Passwordless\FG\X509\CertificateExtensions::fromBinary($binaryData, $offsetIndex);
            } else {
                $attribute = \Akeeba\Passwordless\FG\ASN1\ASNObject::fromBinary($binaryData, $offsetIndex);
            }

            $parsedObject->addAttribute($objectIdentifier, $attribute);
            $octetsToRead -= ($offsetIndex - $initialOffset);
        }

        $parsedObject->setContentLength($contentLength);

        return $parsedObject;
    }
}
