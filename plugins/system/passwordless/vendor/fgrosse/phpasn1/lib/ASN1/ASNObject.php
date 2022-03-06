<?php
/*
 * This file is part of the PHPASN1 library.
 *
 * Copyright © Friedrich Große <friedrich.grosse@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Akeeba\Passwordless\FG\ASN1;

use Akeeba\Passwordless\FG\ASN1\Exception\ParserException;
use Akeeba\Passwordless\FG\ASN1\Universal\BitString;
use Akeeba\Passwordless\FG\ASN1\Universal\Boolean;
use Akeeba\Passwordless\FG\ASN1\Universal\Enumerated;
use Akeeba\Passwordless\FG\ASN1\Universal\GeneralizedTime;
use Akeeba\Passwordless\FG\ASN1\Universal\Integer;
use Akeeba\Passwordless\FG\ASN1\Universal\NullObject;
use Akeeba\Passwordless\FG\ASN1\Universal\ObjectIdentifier;
use Akeeba\Passwordless\FG\ASN1\Universal\RelativeObjectIdentifier;
use Akeeba\Passwordless\FG\ASN1\Universal\OctetString;
use Akeeba\Passwordless\FG\ASN1\Universal\Sequence;
use Akeeba\Passwordless\FG\ASN1\Universal\Set;
use Akeeba\Passwordless\FG\ASN1\Universal\UTCTime;
use Akeeba\Passwordless\FG\ASN1\Universal\IA5String;
use Akeeba\Passwordless\FG\ASN1\Universal\PrintableString;
use Akeeba\Passwordless\FG\ASN1\Universal\NumericString;
use Akeeba\Passwordless\FG\ASN1\Universal\UTF8String;
use Akeeba\Passwordless\FG\ASN1\Universal\UniversalString;
use Akeeba\Passwordless\FG\ASN1\Universal\CharacterString;
use Akeeba\Passwordless\FG\ASN1\Universal\GeneralString;
use Akeeba\Passwordless\FG\ASN1\Universal\VisibleString;
use Akeeba\Passwordless\FG\ASN1\Universal\GraphicString;
use Akeeba\Passwordless\FG\ASN1\Universal\BMPString;
use Akeeba\Passwordless\FG\ASN1\Universal\T61String;
use Akeeba\Passwordless\FG\ASN1\Universal\ObjectDescriptor;
use Akeeba\Passwordless\FG\Utility\BigInteger;
use LogicException;

/**
 * Class ASNObject is the base class for all concrete ASN.1 objects.
 */
abstract class ASNObject implements \Akeeba\Passwordless\FG\ASN1\Parsable
{
    private $contentLength;
    private $nrOfLengthOctets;

    /**
     * Must return the number of octets of the content part.
     *
     * @return int
     */
    abstract protected function calculateContentLength();

    /**
     * Encode the object using DER encoding.
     *
     * @see http://en.wikipedia.org/wiki/X.690#DER_encoding
     *
     * @return string the binary representation of an objects value
     */
    abstract protected function getEncodedValue();

    /**
     * Return the content of this object in a non encoded form.
     * This can be used to print the value in human readable form.
     *
     * @return mixed
     */
    abstract public function getContent();

    /**
     * Return the object type octet.
     * This should use the class constants of Identifier.
     *
     * @see Identifier
     *
     * @return int
     */
    abstract public function getType();

    /**
     * Returns all identifier octets. If an inheriting class models a tag with
     * the long form identifier format, it MUST reimplement this method to
     * return all octets of the identifier.
     *
     * @throws LogicException If the identifier format is long form
     *
     * @return string Identifier as a set of octets
     */
    public function getIdentifier()
    {
        $firstOctet = $this->getType();

        if (\Akeeba\Passwordless\FG\ASN1\Identifier::isLongForm($firstOctet)) {
            throw new LogicException(sprintf('Identifier of %s uses the long form and must therefor override "ASNObject::getIdentifier()".', get_class($this)));
        }

        return chr($firstOctet);
    }

    /**
     * Encode this object using DER encoding.
     *
     * @return string the full binary representation of the complete object
     */
    public function getBinary()
    {
        $result  = $this->getIdentifier();
        $result .= $this->createLengthPart();
        $result .= $this->getEncodedValue();

        return $result;
    }

    private function createLengthPart()
    {
        $contentLength = $this->getContentLength();
        $nrOfLengthOctets = $this->getNumberOfLengthOctets($contentLength);

        if ($nrOfLengthOctets == 1) {
            return chr($contentLength);
        } else {
            // the first length octet determines the number subsequent length octets
            $lengthOctets = chr(0x80 | ($nrOfLengthOctets - 1));
            for ($shiftLength = 8 * ($nrOfLengthOctets - 2); $shiftLength >= 0; $shiftLength -= 8) {
                $lengthOctets .= chr($contentLength >> $shiftLength);
            }

            return $lengthOctets;
        }
    }

    protected function getNumberOfLengthOctets($contentLength = null)
    {
        if (!isset($this->nrOfLengthOctets)) {
            if ($contentLength == null) {
                $contentLength = $this->getContentLength();
            }

            $this->nrOfLengthOctets = 1;
            if ($contentLength > 127) {
                do { // long form
                    $this->nrOfLengthOctets++;
                    $contentLength = $contentLength >> 8;
                } while ($contentLength > 0);
            }
        }

        return $this->nrOfLengthOctets;
    }

    protected function getContentLength()
    {
        if (!isset($this->contentLength)) {
            $this->contentLength = $this->calculateContentLength();
        }

        return $this->contentLength;
    }

    protected function setContentLength($newContentLength)
    {
        $this->contentLength = $newContentLength;
        $this->getNumberOfLengthOctets($newContentLength);
    }

    /**
     * Returns the length of the whole object (including the identifier and length octets).
     */
    public function getObjectLength()
    {
        $nrOfIdentifierOctets = strlen($this->getIdentifier());
        $contentLength = $this->getContentLength();
        $nrOfLengthOctets = $this->getNumberOfLengthOctets($contentLength);

        return $nrOfIdentifierOctets + $nrOfLengthOctets + $contentLength;
    }

    public function __toString()
    {
        return $this->getContent();
    }

    /**
     * Returns the name of the ASN.1 Type of this object.
     *
     * @see Identifier::getName()
     */
    public function getTypeName()
    {
        return \Akeeba\Passwordless\FG\ASN1\Identifier::getName($this->getType());
    }

    /**
     * @param string $binaryData
     * @param int $offsetIndex
     *
     * @throws ParserException
     *
     * @return \FG\ASN1\ASNObject
     */
    public static function fromBinary(&$binaryData, &$offsetIndex = 0)
    {
        if (strlen($binaryData) <= $offsetIndex) {
            throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException('Can not parse binary from data: Offset index larger than input size', $offsetIndex);
        }

        $identifierOctet = ord($binaryData[$offsetIndex]);
        if (\Akeeba\Passwordless\FG\ASN1\Identifier::isContextSpecificClass($identifierOctet) && \Akeeba\Passwordless\FG\ASN1\Identifier::isConstructed($identifierOctet)) {
            return \Akeeba\Passwordless\FG\ASN1\ExplicitlyTaggedObject::fromBinary($binaryData, $offsetIndex);
        }

        switch ($identifierOctet) {
            case \Akeeba\Passwordless\FG\ASN1\Identifier::BITSTRING:
                return \Akeeba\Passwordless\FG\ASN1\Universal\BitString::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::BOOLEAN:
                return \Akeeba\Passwordless\FG\ASN1\Universal\Boolean::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::ENUMERATED:
                return \Akeeba\Passwordless\FG\ASN1\Universal\Enumerated::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::INTEGER:
                return \Akeeba\Passwordless\FG\ASN1\Universal\Integer::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::NULL:
                return \Akeeba\Passwordless\FG\ASN1\Universal\NullObject::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::OBJECT_IDENTIFIER:
                return \Akeeba\Passwordless\FG\ASN1\Universal\ObjectIdentifier::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::RELATIVE_OID:
                return \Akeeba\Passwordless\FG\ASN1\Universal\RelativeObjectIdentifier::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::OCTETSTRING:
                return \Akeeba\Passwordless\FG\ASN1\Universal\OctetString::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::SEQUENCE:
                return \Akeeba\Passwordless\FG\ASN1\Universal\Sequence::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::SET:
                return \Akeeba\Passwordless\FG\ASN1\Universal\Set::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::UTC_TIME:
                return \Akeeba\Passwordless\FG\ASN1\Universal\UTCTime::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::GENERALIZED_TIME:
                return \Akeeba\Passwordless\FG\ASN1\Universal\GeneralizedTime::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::IA5_STRING:
                return \Akeeba\Passwordless\FG\ASN1\Universal\IA5String::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::PRINTABLE_STRING:
                return \Akeeba\Passwordless\FG\ASN1\Universal\PrintableString::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::NUMERIC_STRING:
                return \Akeeba\Passwordless\FG\ASN1\Universal\NumericString::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::UTF8_STRING:
                return \Akeeba\Passwordless\FG\ASN1\Universal\UTF8String::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::UNIVERSAL_STRING:
                return \Akeeba\Passwordless\FG\ASN1\Universal\UniversalString::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::CHARACTER_STRING:
                return \Akeeba\Passwordless\FG\ASN1\Universal\CharacterString::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::GENERAL_STRING:
                return \Akeeba\Passwordless\FG\ASN1\Universal\GeneralString::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::VISIBLE_STRING:
                return \Akeeba\Passwordless\FG\ASN1\Universal\VisibleString::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::GRAPHIC_STRING:
                return \Akeeba\Passwordless\FG\ASN1\Universal\GraphicString::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::BMP_STRING:
                return \Akeeba\Passwordless\FG\ASN1\Universal\BMPString::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::T61_STRING:
                return \Akeeba\Passwordless\FG\ASN1\Universal\T61String::fromBinary($binaryData, $offsetIndex);
            case \Akeeba\Passwordless\FG\ASN1\Identifier::OBJECT_DESCRIPTOR:
                return \Akeeba\Passwordless\FG\ASN1\Universal\ObjectDescriptor::fromBinary($binaryData, $offsetIndex);
            default:
                // At this point the identifier may be >1 byte.
                if (\Akeeba\Passwordless\FG\ASN1\Identifier::isConstructed($identifierOctet)) {
                    return new \Akeeba\Passwordless\FG\ASN1\UnknownConstructedObject($binaryData, $offsetIndex);
                } else {
                    $identifier = self::parseBinaryIdentifier($binaryData, $offsetIndex);
                    $lengthOfUnknownObject = self::parseContentLength($binaryData, $offsetIndex);
                    $offsetIndex += $lengthOfUnknownObject;

                    return new \Akeeba\Passwordless\FG\ASN1\UnknownObject($identifier, $lengthOfUnknownObject);
                }
        }
    }

    protected static function parseIdentifier($identifierOctet, $expectedIdentifier, $offsetForExceptionHandling)
    {
        if (is_string($identifierOctet) || is_numeric($identifierOctet) == false) {
            $identifierOctet = ord($identifierOctet);
        }

        if ($identifierOctet != $expectedIdentifier) {
            $message = 'Can not create an '.\Akeeba\Passwordless\FG\ASN1\Identifier::getName($expectedIdentifier).' from an '.\Akeeba\Passwordless\FG\ASN1\Identifier::getName($identifierOctet);
            throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException($message, $offsetForExceptionHandling);
        }
    }

    protected static function parseBinaryIdentifier($binaryData, &$offsetIndex)
    {
        if (strlen($binaryData) <= $offsetIndex) {
            throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException('Can not parse identifier from data: Offset index larger than input size', $offsetIndex);
        }

        $identifier = $binaryData[$offsetIndex++];

        if (\Akeeba\Passwordless\FG\ASN1\Identifier::isLongForm(ord($identifier)) == false) {
            return $identifier;
        }

        while (true) {
            if (strlen($binaryData) <= $offsetIndex) {
                throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException('Can not parse identifier (long form) from data: Offset index larger than input size', $offsetIndex);
            }
            $nextOctet = $binaryData[$offsetIndex++];
            $identifier .= $nextOctet;

            if ((ord($nextOctet) & 0x80) === 0) {
                // the most significant bit is 0 to we have reached the end of the identifier
                break;
            }
        }

        return $identifier;
    }

    protected static function parseContentLength(&$binaryData, &$offsetIndex, $minimumLength = 0)
    {
        if (strlen($binaryData) <= $offsetIndex) {
            throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException('Can not parse content length from data: Offset index larger than input size', $offsetIndex);
        }

        $contentLength = ord($binaryData[$offsetIndex++]);
        if (($contentLength & 0x80) != 0) {
            // bit 8 is set -> this is the long form
            $nrOfLengthOctets = $contentLength & 0x7F;
            $contentLength = \Akeeba\Passwordless\FG\Utility\BigInteger::create(0x00);
            for ($i = 0; $i < $nrOfLengthOctets; $i++) {
                if (strlen($binaryData) <= $offsetIndex) {
                    throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException('Can not parse content length (long form) from data: Offset index larger than input size', $offsetIndex);
                }
                $contentLength = $contentLength->shiftLeft(8)->add(ord($binaryData[$offsetIndex++]));
            }

            if ($contentLength->compare(PHP_INT_MAX) > 0) {
                throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException("Can not parse content length from data: length > maximum integer", $offsetIndex);
            }

            $contentLength = $contentLength->toInteger();
        }

        if ($contentLength < $minimumLength) {
            throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException('A '.get_called_class()." should have a content length of at least {$minimumLength}. Extracted length was {$contentLength}", $offsetIndex);
        }

        $lenDataRemaining = strlen($binaryData) - $offsetIndex;

        if ($lenDataRemaining < $contentLength) {
            throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException("Content length {$contentLength} exceeds remaining data length {$lenDataRemaining}", $offsetIndex);
        }

        return $contentLength;
    }
}
