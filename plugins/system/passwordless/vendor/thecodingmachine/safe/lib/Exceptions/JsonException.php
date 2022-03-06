<?php


namespace Akeeba\Passwordless\Safe\Exceptions;

class JsonException extends \Exception implements \Akeeba\Passwordless\Safe\Exceptions\Akeeba\Passwordless\SafeExceptionInterface
{
    public static function createFromPhpError(): self
    {
        return new self(\json_last_error_msg(), \json_last_error());
    }
}
