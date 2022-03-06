<?php


namespace Akeeba\Passwordless\Safe\Exceptions;

class CurlException extends \Exception implements \Akeeba\Passwordless\Safe\Exceptions\Akeeba\Passwordless\SafeExceptionInterface
{
    /**
     * @param resource $ch
     */
    public static function createFromCurlResource($ch): self
    {
        return new self(\curl_error($ch), \curl_errno($ch));
    }
}
