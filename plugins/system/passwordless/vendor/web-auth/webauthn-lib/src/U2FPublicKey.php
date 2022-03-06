<?php

namespace Akeeba\Passwordless\Webauthn;

use Akeeba\Passwordless\CBOR\ByteStringObject;
use Akeeba\Passwordless\CBOR\MapItem;
use Akeeba\Passwordless\CBOR\MapObject;
use Akeeba\Passwordless\CBOR\NegativeIntegerObject;
use Akeeba\Passwordless\CBOR\UnsignedIntegerObject;

class U2FPublicKey
{
    public static function isU2FKey($publicKey): bool
    {
        return $publicKey[0] === "\x04";
    }

    public static function createCOSEKey($publicKey): string
    {

        $mapObject = new \Akeeba\Passwordless\CBOR\MapObject([
            1 => \Akeeba\Passwordless\CBOR\MapItem::create(
                new \Akeeba\Passwordless\CBOR\UnsignedIntegerObject(1, null),
                new \Akeeba\Passwordless\CBOR\UnsignedIntegerObject(2, null)
            ),
            3 => \Akeeba\Passwordless\CBOR\MapItem::create(
                new \Akeeba\Passwordless\CBOR\UnsignedIntegerObject(3, null),
                new \Akeeba\Passwordless\CBOR\NegativeIntegerObject(6, null)
            ),
            -1 => \Akeeba\Passwordless\CBOR\MapItem::create(
                new \Akeeba\Passwordless\CBOR\NegativeIntegerObject(0, null),
                new \Akeeba\Passwordless\CBOR\UnsignedIntegerObject(1, null)
            ),
            -2 => \Akeeba\Passwordless\CBOR\MapItem::create(
                new \Akeeba\Passwordless\CBOR\NegativeIntegerObject(1, null),
                new \Akeeba\Passwordless\CBOR\ByteStringObject(substr($publicKey, 1, 32))
            ),
            -3 => \Akeeba\Passwordless\CBOR\MapItem::create(
                new \Akeeba\Passwordless\CBOR\NegativeIntegerObject(2, null),
                new \Akeeba\Passwordless\CBOR\ByteStringObject(substr($publicKey, 33))
            ),
        ]);

        return $mapObject->__toString();
    }
}
