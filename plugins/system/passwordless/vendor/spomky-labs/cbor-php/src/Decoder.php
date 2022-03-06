<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Akeeba\Passwordless\CBOR;

use Akeeba\Passwordless\CBOR\OtherObject\BreakObject;
use Akeeba\Passwordless\CBOR\OtherObject\DoublePrecisionFloatObject;
use Akeeba\Passwordless\CBOR\OtherObject\FalseObject;
use Akeeba\Passwordless\CBOR\OtherObject\HalfPrecisionFloatObject;
use Akeeba\Passwordless\CBOR\OtherObject\NullObject;
use Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManager;
use Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManagerInterface;
use Akeeba\Passwordless\CBOR\OtherObject\SimpleObject;
use Akeeba\Passwordless\CBOR\OtherObject\SinglePrecisionFloatObject;
use Akeeba\Passwordless\CBOR\OtherObject\TrueObject;
use Akeeba\Passwordless\CBOR\OtherObject\UndefinedObject;
use Akeeba\Passwordless\CBOR\Tag\Base16EncodingTag;
use Akeeba\Passwordless\CBOR\Tag\Base64EncodingTag;
use Akeeba\Passwordless\CBOR\Tag\Base64Tag;
use Akeeba\Passwordless\CBOR\Tag\Base64UrlEncodingTag;
use Akeeba\Passwordless\CBOR\Tag\Base64UrlTag;
use Akeeba\Passwordless\CBOR\Tag\BigFloatTag;
use Akeeba\Passwordless\CBOR\Tag\Akeeba\Passwordless\CBOREncodingTag;
use Akeeba\Passwordless\CBOR\Tag\Akeeba\Passwordless\CBORTag;
use Akeeba\Passwordless\CBOR\Tag\DatetimeTag;
use Akeeba\Passwordless\CBOR\Tag\DecimalFractionTag;
use Akeeba\Passwordless\CBOR\Tag\MimeTag;
use Akeeba\Passwordless\CBOR\Tag\NegativeBigIntegerTag;
use Akeeba\Passwordless\CBOR\Tag\TagManager;
use Akeeba\Passwordless\CBOR\Tag\TagManagerInterface;
use Akeeba\Passwordless\CBOR\Tag\TimestampTag;
use Akeeba\Passwordless\CBOR\Tag\UnsignedBigIntegerTag;
use Akeeba\Passwordless\CBOR\Tag\UriTag;
use InvalidArgumentException;
use function ord;
use RuntimeException;
use const STR_PAD_LEFT;

final class Decoder implements \Akeeba\Passwordless\CBOR\DecoderInterface
{
    /**
     * @var Tag\TagManagerInterface
     */
    private $tagManager;

    /**
     * @var OtherObject\OtherObjectManagerInterface
     */
    private $otherObjectManager;

    public function __construct(
        ?\Akeeba\Passwordless\CBOR\Tag\TagManagerInterface $tagManager = null,
        ?\Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManagerInterface $otherTypeManager = null
    ) {
        $this->tagManager = $tagManager ?? $this->generateTagManager();
        $this->otherObjectManager = $otherTypeManager ?? $this->generateOtherObjectManager();
    }

    public static function create(
        ?\Akeeba\Passwordless\CBOR\Tag\TagManagerInterface $tagManager = null,
        ?\Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManagerInterface $otherObjectManager = null
    ): self {
        return new self($tagManager, $otherObjectManager);
    }

    public function withTagManager(\Akeeba\Passwordless\CBOR\Tag\TagManagerInterface $tagManager): self
    {
        $this->tagManager = $tagManager;

        return $this;
    }

    public function withOtherObjectManager(\Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManagerInterface $otherObjectManager): self
    {
        $this->otherObjectManager = $otherObjectManager;

        return $this;
    }

    public function decode(\Akeeba\Passwordless\CBOR\Stream $stream): \Akeeba\Passwordless\CBOR\CBORObject
    {
        return $this->process($stream, false);
    }

    private function process(\Akeeba\Passwordless\CBOR\Stream $stream, bool $breakable): \Akeeba\Passwordless\CBOR\CBORObject
    {
        $ib = ord($stream->read(1));
        $mt = $ib >> 5;
        $ai = $ib & 0b00011111;
        $val = null;
        switch ($ai) {
            case \Akeeba\Passwordless\CBOR\CBORObject::LENGTH_1_BYTE: //24
            case \Akeeba\Passwordless\CBOR\CBORObject::LENGTH_2_BYTES: //25
            case \Akeeba\Passwordless\CBOR\CBORObject::LENGTH_4_BYTES: //26
            case \Akeeba\Passwordless\CBOR\CBORObject::LENGTH_8_BYTES: //27
                $val = $stream->read(2 ** ($ai & 0b00000111));
                break;
            case \Akeeba\Passwordless\CBOR\CBORObject::FUTURE_USE_1: //28
            case \Akeeba\Passwordless\CBOR\CBORObject::FUTURE_USE_2: //29
            case \Akeeba\Passwordless\CBOR\CBORObject::FUTURE_USE_3: //30
                throw new InvalidArgumentException(sprintf(
                    'Cannot parse the data. Found invalid Additional Information "%s" (%d).',
                    str_pad(decbin($ai), 8, '0', STR_PAD_LEFT),
                    $ai
                ));
            case \Akeeba\Passwordless\CBOR\CBORObject::LENGTH_INDEFINITE: //31
                return $this->processInfinite($stream, $mt, $breakable);
        }

        return $this->processFinite($stream, $mt, $ai, $val);
    }

    private function processFinite(\Akeeba\Passwordless\CBOR\Stream $stream, int $mt, int $ai, ?string $val): \Akeeba\Passwordless\CBOR\CBORObject
    {
        switch ($mt) {
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_UNSIGNED_INTEGER: //0
                return \Akeeba\Passwordless\CBOR\UnsignedIntegerObject::createObjectForValue($ai, $val);
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_NEGATIVE_INTEGER: //1
                return \Akeeba\Passwordless\CBOR\NegativeIntegerObject::createObjectForValue($ai, $val);
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_BYTE_STRING: //2
                $length = $val === null ? $ai : \Akeeba\Passwordless\CBOR\Utils::binToInt($val);

                return \Akeeba\Passwordless\CBOR\ByteStringObject::create($stream->read($length));
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_TEXT_STRING: //3
                $length = $val === null ? $ai : \Akeeba\Passwordless\CBOR\Utils::binToInt($val);

                return \Akeeba\Passwordless\CBOR\TextStringObject::create($stream->read($length));
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_LIST: //4
                $object = \Akeeba\Passwordless\CBOR\ListObject::create();
                $nbItems = $val === null ? $ai : \Akeeba\Passwordless\CBOR\Utils::binToInt($val);
                for ($i = 0; $i < $nbItems; ++$i) {
                    $object->add($this->process($stream, false));
                }

                return $object;
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_MAP: //5
                $object = \Akeeba\Passwordless\CBOR\MapObject::create();
                $nbItems = $val === null ? $ai : \Akeeba\Passwordless\CBOR\Utils::binToInt($val);
                for ($i = 0; $i < $nbItems; ++$i) {
                    $object->add($this->process($stream, false), $this->process($stream, false));
                }

                return $object;
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_TAG: //6
                return $this->tagManager->createObjectForValue($ai, $val, $this->process($stream, false));
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_OTHER_TYPE: //7
                return $this->otherObjectManager->createObjectForValue($ai, $val);
            default:
                throw new RuntimeException(sprintf(
                    'Unsupported major type "%s" (%d).',
                    str_pad(decbin($mt), 5, '0', STR_PAD_LEFT),
                    $mt
                )); // Should never append
        }
    }

    private function processInfinite(\Akeeba\Passwordless\CBOR\Stream $stream, int $mt, bool $breakable): \Akeeba\Passwordless\CBOR\CBORObject
    {
        switch ($mt) {
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_BYTE_STRING: //2
                $object = \Akeeba\Passwordless\CBOR\IndefiniteLengthByteStringObject::create();
                while (! ($it = $this->process($stream, true)) instanceof \Akeeba\Passwordless\CBOR\OtherObject\BreakObject) {
                    if (! $it instanceof \Akeeba\Passwordless\CBOR\ByteStringObject) {
                        throw new RuntimeException(
                            'Unable to parse the data. Infinite Byte String object can only get Byte String objects.'
                        );
                    }
                    $object->add($it);
                }

                return $object;
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_TEXT_STRING: //3
                $object = \Akeeba\Passwordless\CBOR\IndefiniteLengthTextStringObject::create();
                while (! ($it = $this->process($stream, true)) instanceof \Akeeba\Passwordless\CBOR\OtherObject\BreakObject) {
                    if (! $it instanceof \Akeeba\Passwordless\CBOR\TextStringObject) {
                        throw new RuntimeException(
                            'Unable to parse the data. Infinite Text String object can only get Text String objects.'
                        );
                    }
                    $object->add($it);
                }

                return $object;
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_LIST: //4
                $object = \Akeeba\Passwordless\CBOR\IndefiniteLengthListObject::create();
                $it = $this->process($stream, true);
                while (! $it instanceof \Akeeba\Passwordless\CBOR\OtherObject\BreakObject) {
                    $object->add($it);
                    $it = $this->process($stream, true);
                }

                return $object;
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_MAP: //5
                $object = \Akeeba\Passwordless\CBOR\IndefiniteLengthMapObject::create();
                while (! ($it = $this->process($stream, true)) instanceof \Akeeba\Passwordless\CBOR\OtherObject\BreakObject) {
                    $object->add($it, $this->process($stream, false));
                }

                return $object;
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_OTHER_TYPE: //7
                if (! $breakable) {
                    throw new InvalidArgumentException('Cannot parse the data. No enclosing indefinite.');
                }

                return \Akeeba\Passwordless\CBOR\OtherObject\BreakObject::create();
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_UNSIGNED_INTEGER: //0
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_NEGATIVE_INTEGER: //1
            case \Akeeba\Passwordless\CBOR\CBORObject::MAJOR_TYPE_TAG: //6
            default:
                throw new InvalidArgumentException(sprintf(
                    'Cannot parse the data. Found infinite length for Major Type "%s" (%d).',
                    str_pad(decbin($mt), 5, '0', STR_PAD_LEFT),
                    $mt
                ));
        }
    }

    private function generateTagManager(): \Akeeba\Passwordless\CBOR\Tag\TagManagerInterface
    {
        return \Akeeba\Passwordless\CBOR\Tag\TagManager::create()
            ->add(\Akeeba\Passwordless\CBOR\Tag\DatetimeTag::class)
            ->add(\Akeeba\Passwordless\CBOR\Tag\TimestampTag::class)

            ->add(\Akeeba\Passwordless\CBOR\Tag\UnsignedBigIntegerTag::class)
            ->add(\Akeeba\Passwordless\CBOR\Tag\NegativeBigIntegerTag::class)

            ->add(\Akeeba\Passwordless\CBOR\Tag\DecimalFractionTag::class)
            ->add(\Akeeba\Passwordless\CBOR\Tag\BigFloatTag::class)

            ->add(\Akeeba\Passwordless\CBOR\Tag\Base64UrlEncodingTag::class)
            ->add(\Akeeba\Passwordless\CBOR\Tag\Base64EncodingTag::class)
            ->add(\Akeeba\Passwordless\CBOR\Tag\Base16EncodingTag::class)
            ->add(\Akeeba\Passwordless\CBOR\Tag\Akeeba\Passwordless\CBOREncodingTag::class)

            ->add(\Akeeba\Passwordless\CBOR\Tag\UriTag::class)
            ->add(\Akeeba\Passwordless\CBOR\Tag\Base64UrlTag::class)
            ->add(\Akeeba\Passwordless\CBOR\Tag\Base64Tag::class)
            ->add(\Akeeba\Passwordless\CBOR\Tag\MimeTag::class)

            ->add(\Akeeba\Passwordless\CBOR\Tag\Akeeba\Passwordless\CBORTag::class)
        ;
    }

    private function generateOtherObjectManager(): \Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManagerInterface
    {
        return \Akeeba\Passwordless\CBOR\OtherObject\OtherObjectManager::create()
            ->add(\Akeeba\Passwordless\CBOR\OtherObject\BreakObject::class)
            ->add(\Akeeba\Passwordless\CBOR\OtherObject\SimpleObject::class)
            ->add(\Akeeba\Passwordless\CBOR\OtherObject\FalseObject::class)
            ->add(\Akeeba\Passwordless\CBOR\OtherObject\TrueObject::class)
            ->add(\Akeeba\Passwordless\CBOR\OtherObject\NullObject::class)
            ->add(\Akeeba\Passwordless\CBOR\OtherObject\UndefinedObject::class)
            ->add(\Akeeba\Passwordless\CBOR\OtherObject\HalfPrecisionFloatObject::class)
            ->add(\Akeeba\Passwordless\CBOR\OtherObject\SinglePrecisionFloatObject::class)
            ->add(\Akeeba\Passwordless\CBOR\OtherObject\DoublePrecisionFloatObject::class)
            ;
    }
}
