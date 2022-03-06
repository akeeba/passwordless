<?php
namespace Akeeba\Passwordless\Safe\Exceptions;

class Ssh2Exception extends \ErrorException implements \Akeeba\Passwordless\Safe\Exceptions\Akeeba\Passwordless\SafeExceptionInterface
{
    public static function createFromPhpError(): self
    {
        $error = error_get_last();
        return new self($error['message'] ?? 'An error occured', 0, $error['type'] ?? 1);
    }
}
