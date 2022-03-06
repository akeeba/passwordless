<?php


namespace Akeeba\Passwordless\Safe\Exceptions;

class OpensslException extends \Exception implements \Akeeba\Passwordless\Safe\Exceptions\Akeeba\Passwordless\SafeExceptionInterface
{
    public static function createFromPhpError(): self
    {
        return new self(\openssl_error_string() ?: '', 0);
    }
}
