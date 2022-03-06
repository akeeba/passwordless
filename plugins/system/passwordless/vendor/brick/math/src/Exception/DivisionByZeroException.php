<?php

declare(strict_types=1);

namespace Akeeba\Passwordless\Brick\Math\Exception;

/**
 * Exception thrown when a division by zero occurs.
 */
class DivisionByZeroException extends \Akeeba\Passwordless\Brick\Math\Exception\MathException
{
    /**
     * @return DivisionByZeroException
     *
     * @psalm-pure
     */
    public static function divisionByZero() : \Akeeba\Passwordless\Brick\Math\Exception\DivisionByZeroException
    {
        return new self('Division by zero.');
    }

    /**
     * @return DivisionByZeroException
     *
     * @psalm-pure
     */
    public static function modulusMustNotBeZero() : \Akeeba\Passwordless\Brick\Math\Exception\DivisionByZeroException
    {
        return new self('The modulus must not be zero.');
    }

    /**
     * @return DivisionByZeroException
     *
     * @psalm-pure
     */
    public static function denominatorMustNotBeZero() : \Akeeba\Passwordless\Brick\Math\Exception\DivisionByZeroException
    {
        return new self('The denominator of a rational number cannot be zero.');
    }
}
