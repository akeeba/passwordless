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

use ArrayAccess;
use ArrayIterator;
use Countable;
use Akeeba\Passwordless\FG\ASN1\Exception\ParserException;
use Iterator;

abstract class Construct extends \Akeeba\Passwordless\FG\ASN1\ASNObject implements Countable, ArrayAccess, Iterator, \Akeeba\Passwordless\FG\ASN1\Parsable
{
    /** @var \FG\ASN1\ASNObject[] */
    protected $children;
    private $iteratorPosition;

    /**
     * @param \FG\ASN1\ASNObject[] $children the variadic type hint is commented due to https://github.com/facebook/hhvm/issues/4858
     */
    public function __construct(/* HH_FIXME[4858]: variadic + strict */ ...$children)
    {
        $this->children = $children;
        $this->iteratorPosition = 0;
    }

    public function getContent()
    {
        return $this->children;
    }

    #[\ReturnTypeWillChange]
    public function rewind()
    {
        $this->iteratorPosition = 0;
    }

    #[\ReturnTypeWillChange]
    public function current()
    {
        return $this->children[$this->iteratorPosition];
    }

    #[\ReturnTypeWillChange]
    public function key()
    {
        return $this->iteratorPosition;
    }

    #[\ReturnTypeWillChange]
    public function next()
    {
        $this->iteratorPosition++;
    }

    #[\ReturnTypeWillChange]
    public function valid()
    {
        return isset($this->children[$this->iteratorPosition]);
    }

    #[\ReturnTypeWillChange]
    public function offsetExists($offset)
    {
        return array_key_exists($offset, $this->children);
    }

    #[\ReturnTypeWillChange]
    public function offsetGet($offset)
    {
        return $this->children[$offset];
    }

    #[\ReturnTypeWillChange]
    public function offsetSet($offset, $value)
    {
        if ($offset === null) {
            $offset = count($this->children);
        }

        $this->children[$offset] = $value;
    }

    #[\ReturnTypeWillChange]
    public function offsetUnset($offset)
    {
        unset($this->children[$offset]);
    }

    protected function calculateContentLength()
    {
        $length = 0;
        foreach ($this->children as $component) {
            $length += $component->getObjectLength();
        }

        return $length;
    }

    protected function getEncodedValue()
    {
        $result = '';
        foreach ($this->children as $component) {
            $result .= $component->getBinary();
        }

        return $result;
    }

    public function addChild(\Akeeba\Passwordless\FG\ASN1\ASNObject $child)
    {
        $this->children[] = $child;
    }

    public function addChildren(array $children)
    {
        foreach ($children as $child) {
            $this->addChild($child);
        }
    }

    public function __toString()
    {
        $nrOfChildren = $this->getNumberOfChildren();
        $childString = $nrOfChildren == 1 ? 'child' : 'children';

        return "[{$nrOfChildren} {$childString}]";
    }

    public function getNumberOfChildren()
    {
        return count($this->children);
    }

    /**
     * @return \FG\ASN1\ASNObject[]
     */
    public function getChildren()
    {
        return $this->children;
    }

    /**
     * @return \FG\ASN1\ASNObject
     */
    public function getFirstChild()
    {
        return $this->children[0];
    }

    /**
     * @param string $binaryData
     * @param int $offsetIndex
     *
     * @throws Exception\ParserException
     *
     * @return Construct|static
     */
    #[\ReturnTypeWillChange]
    public static function fromBinary(&$binaryData, &$offsetIndex = 0)
    {
        $parsedObject = new static();
        self::parseIdentifier($binaryData[$offsetIndex], $parsedObject->getType(), $offsetIndex++);
        $contentLength = self::parseContentLength($binaryData, $offsetIndex);
        $startIndex = $offsetIndex;

        $children = [];
        $octetsToRead = $contentLength;
        while ($octetsToRead > 0) {
            $newChild = \Akeeba\Passwordless\FG\ASN1\ASNObject::fromBinary($binaryData, $offsetIndex);
            $octetsToRead -= $newChild->getObjectLength();
            $children[] = $newChild;
        }

        if ($octetsToRead !== 0) {
            throw new \Akeeba\Passwordless\FG\ASN1\Exception\ParserException("Sequence length incorrect", $startIndex);
        }

        $parsedObject->addChildren($children);
        $parsedObject->setContentLength($contentLength);

        return $parsedObject;
    }

    #[\ReturnTypeWillChange]
    public function count($mode = COUNT_NORMAL)
    {
        return count($this->children, $mode);
    }

    public function getIterator()
    {
        return new ArrayIterator($this->children);
    }
}