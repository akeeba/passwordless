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

use Akeeba\Passwordless\FG\ASN1\Exception\ParserException;
use Akeeba\Passwordless\FG\ASN1\OID;
use Akeeba\Passwordless\FG\ASN1\ASNObject;
use Akeeba\Passwordless\FG\ASN1\Parsable;
use Akeeba\Passwordless\FG\ASN1\Identifier;
use Akeeba\Passwordless\FG\ASN1\Universal\OctetString;
use Akeeba\Passwordless\FG\ASN1\Universal\Set;
use Akeeba\Passwordless\FG\ASN1\Universal\Sequence;
use Akeeba\Passwordless\FG\ASN1\Universal\ObjectIdentifier;
use Akeeba\Passwordless\FG\X509\SAN\SubjectAlternativeNames;

class CertificateExtensions extends \Akeeba\Passwordless\FG\ASN1\Universal\Set implements \Akeeba\Passwordless\FG\ASN1\Parsable
{
    private $innerSequence;
    private $extensions = [];

    public function __construct()
    {
        $this->innerSequence = new \Akeeba\Passwordless\FG\ASN1\Universal\Sequence();
        parent::__construct($this->innerSequence);
    }

    public function addSubjectAlternativeNames(\Akeeba\Passwordless\FG\X509\SAN\SubjectAlternativeNames $sans)
    {
        $this->addExtension(\Akeeba\Passwordless\FG\ASN1\OID::CERT_EXT_SUBJECT_ALT_NAME, $sans);
    }

    private function addExtension($oidString, \Akeeba\Passwordless\FG\ASN1\ASNObject $extension)
    {
        $sequence = new \Akeeba\Passwordless\FG\ASN1\Universal\Sequence();
        $sequence->addChild(new \Akeeba\Passwordless\FG\ASN1\Universal\ObjectIdentifier($oidString));
        $sequence->addChild($extension);

        $this->innerSequence->addChild($sequence);
        $this->extensions[] = $extension;
    }

    public function getContent()
    {
        return $this->extensions;
    }

    public static function fromBinary(&$binaryData, &$offsetIndex = 0)
    {
        self::parseIdentifier($binaryData[$offsetIndex], \Akeeba\Passwordless\FG\ASN1\Identifier::SET, $offsetIndex++);
        self::parseContentLength($binaryData, $offsetIndex);

        $tmpOffset = $offsetIndex;
        $extensions = \Akeeba\Passwordless\FG\ASN1\Universal\Sequence::fromBinary($binaryData, $offsetIndex);
        $tmpOffset += 1 + $extensions->getNumberOfLengthOctets();

        $parsedObject = new self();
        foreach ($extensions as $extension) {
            if ($extension->getType() != \Akeeba\Passwordless\FG\ASN1\Identifier::SEQUENCE) {
                //FIXME wrong offset index
                throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException('Could not parse Certificate Extensions: Expected ASN.1 Sequence but got '.$extension->getTypeName(), $offsetIndex);
            }

            $tmpOffset += 1 + $extension->getNumberOfLengthOctets();
            $children = $extension->getChildren();
            if (count($children) < 2) {
                throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException('Could not parse Certificate Extensions: Needs at least two child elements per extension sequence (object identifier and octet string)', $tmpOffset);
            }
            /** @var \FG\ASN1\ASNObject $objectIdentifier */
            $objectIdentifier = $children[0];

            /** @var OctetString $octetString */
            $octetString = $children[1];

            if ($objectIdentifier->getType() != \Akeeba\Passwordless\FG\ASN1\Identifier::OBJECT_IDENTIFIER) {
                throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException('Could not parse Certificate Extensions: Expected ASN.1 Object Identifier but got '.$extension->getTypeName(), $tmpOffset);
            }

            $tmpOffset += $objectIdentifier->getObjectLength();

            if ($objectIdentifier->getContent() == \Akeeba\Passwordless\FG\ASN1\OID::CERT_EXT_SUBJECT_ALT_NAME) {
                $sans = \Akeeba\Passwordless\FG\X509\SAN\SubjectAlternativeNames::fromBinary($binaryData, $tmpOffset);
                $parsedObject->addSubjectAlternativeNames($sans);
            } else {
                // can now only parse SANs. There might be more in the future
                $tmpOffset += $octetString->getObjectLength();
            }
        }

        $parsedObject->getBinary(); // Determine the number of content octets and object sizes once (just to let the equality unit tests pass :/ )
        return $parsedObject;
    }
}
