<?php

if (\PHP_VERSION_ID < 80000 && \extension_loaded('tokenizer')) {
    class PhpToken extends \Akeeba\Passwordless\Symfony\Polyfill\Php80\PhpToken
    {
    }
}
