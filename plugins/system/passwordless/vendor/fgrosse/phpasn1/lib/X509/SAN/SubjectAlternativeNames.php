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

use Akeeba\Passwordless\FG\ASN1\Exception\ParserException;
use Akeeba\Passwordless\FG\ASN1\ASNObject;
use Akeeba\Passwordless\FG\ASN1\OID;
use Akeeba\Passwordless\FG\ASN1\Parsable;
use Akeeba\Passwordless\FG\ASN1\Identifier;
use Akeeba\Passwordless\FG\ASN1\Universal\Sequence;

/**
 * See section 8.3.2.1 of ITU-T X.509.
 */
class SubjectAlternativeNames extends \Akeeba\Passwordless\FG\ASN1\ASNObject implements \Akeeba\Passwordless\FG\ASN1\Parsable
{
    private $alternativeNamesSequence;

    public function __construct()
    {
        $this->alternativeNamesSequence = new \Akeeba\Passwordless\FG\ASN1\Universal\Sequence();
    }

    protected function calculateContentLength()
    {
        return $this->alternativeNamesSequence->getObjectLength();
    }

    public function getType()
    {
        return \Akeeba\Passwordless\FG\ASN1\Identifier::OCTETSTRING;
    }

    public function addDomainName(\Akeeba\Passwordless\FG\X509\SAN\DNSName $domainName)
    {
        $this->alternativeNamesSequence->addChild($domainName);
    }

    public function addIP(\Akeeba\Passwordless\FG\X509\SAN\IPAddress $ip)
    {
        $this->alternativeNamesSequence->addChild($ip);
    }

    public function getContent()
    {
        return $this->alternativeNamesSequence->getContent();
    }

    protected function getEncodedValue()
    {
        return $this->alternativeNamesSequence->getBinary();
    }

    public static function fromBinary(&$binaryData, &$offsetIndex = 0)
    {
        self::parseIdentifier($binaryData[$offsetIndex], \Akeeba\Passwordless\FG\ASN1\Identifier::OCTETSTRING, $offsetIndex++);
        $contentLength = self::parseContentLength($binaryData, $offsetIndex);

        if ($contentLength < 2) {
            throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException('Can not parse Subject Alternative Names: The Sequence within the octet string after the Object identifier '.\Akeeba\Passwordless\FG\ASN1\OID::CERT_EXT_SUBJECT_ALT_NAME." is too short ({$contentLength} octets)", $offsetIndex);
        }

        $offsetOfSequence = $offsetIndex;
        $sequence = \Akeeba\Passwordless\FG\ASN1\Universal\Sequence::fromBinary($binaryData, $offsetIndex);
        $offsetOfSequence += $sequence->getNumberOfLengthOctets() + 1;

        if ($sequence->getObjectLength() != $contentLength) {
            throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException('Can not parse Subject Alternative Names: The Sequence length does not match the length of the surrounding octet string', $offsetIndex);
        }

        $parsedObject = new self();
        /** @var \FG\ASN1\ASNObject $object */
        foreach ($sequence as $object) {
            if ($object->getType() == \Akeeba\Passwordless\FG\X509\SAN\DNSName::IDENTIFIER) {
                $domainName = \Akeeba\Passwordless\FG\X509\SAN\DNSName::fromBinary($binaryData, $offsetOfSequence);
                $parsedObject->addDomainName($domainName);
            } elseif ($object->getType() == \Akeeba\Passwordless\FG\X509\SAN\IPAddress::IDENTIFIER) {
                $ip = \Akeeba\Passwordless\FG\X509\SAN\IPAddress::fromBinary($binaryData, $offsetOfSequence);
                $parsedObject->addIP($ip);
            } else {
                throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException('Could not parse Subject Alternative Name: Only DNSName and IP SANs are currently supported', $offsetIndex);
            }
        }

        $parsedObject->getBinary(); // Determine the number of content octets and object sizes once (just to let the equality unit tests pass :/ )
        return $parsedObject;
    }
}
