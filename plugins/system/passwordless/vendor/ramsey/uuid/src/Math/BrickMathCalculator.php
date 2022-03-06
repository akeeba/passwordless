<?php

/**
 * This file is part of the ramsey/uuid library
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @copyright Copyright (c) Ben Ramsey <ben@benramsey.com>
 * @license http://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace Akeeba\Passwordless\Ramsey\Uuid\Math;

use Akeeba\Passwordless\Brick\Math\BigDecimal;
use Akeeba\Passwordless\Brick\Math\BigInteger;
use Akeeba\Passwordless\Brick\Math\Exception\MathException;
use Akeeba\Passwordless\Brick\Math\RoundingMode as BrickMathRounding;
use Akeeba\Passwordless\Ramsey\Uuid\Exception\InvalidArgumentException;
use Akeeba\Passwordless\Ramsey\Uuid\Type\Decimal;
use Akeeba\Passwordless\Ramsey\Uuid\Type\Hexadecimal;
use Akeeba\Passwordless\Ramsey\Uuid\Type\Integer as IntegerObject;
use Akeeba\Passwordless\Ramsey\Uuid\Type\NumberInterface;

/**
 * A calculator using the brick/math library for arbitrary-precision arithmetic
 *
 * @psalm-immutable
 */
final class BrickMathCalculator implements \Akeeba\Passwordless\Ramsey\Uuid\Math\CalculatorInterface
{
    private const ROUNDING_MODE_MAP = [
        \Akeeba\Passwordless\Ramsey\Uuid\Math\RoundingMode::UNNECESSARY => \Akeeba\Passwordless\Brick\Math\RoundingMode::UNNECESSARY,
        \Akeeba\Passwordless\Ramsey\Uuid\Math\RoundingMode::UP => \Akeeba\Passwordless\Brick\Math\RoundingMode::UP,
        \Akeeba\Passwordless\Ramsey\Uuid\Math\RoundingMode::DOWN => \Akeeba\Passwordless\Brick\Math\RoundingMode::DOWN,
        \Akeeba\Passwordless\Ramsey\Uuid\Math\RoundingMode::CEILING => \Akeeba\Passwordless\Brick\Math\RoundingMode::CEILING,
        \Akeeba\Passwordless\Ramsey\Uuid\Math\RoundingMode::FLOOR => \Akeeba\Passwordless\Brick\Math\RoundingMode::FLOOR,
        \Akeeba\Passwordless\Ramsey\Uuid\Math\RoundingMode::HALF_UP => \Akeeba\Passwordless\Brick\Math\RoundingMode::HALF_UP,
        \Akeeba\Passwordless\Ramsey\Uuid\Math\RoundingMode::HALF_DOWN => \Akeeba\Passwordless\Brick\Math\RoundingMode::HALF_DOWN,
        \Akeeba\Passwordless\Ramsey\Uuid\Math\RoundingMode::HALF_CEILING => \Akeeba\Passwordless\Brick\Math\RoundingMode::HALF_CEILING,
        \Akeeba\Passwordless\Ramsey\Uuid\Math\RoundingMode::HALF_FLOOR => \Akeeba\Passwordless\Brick\Math\RoundingMode::HALF_FLOOR,
        \Akeeba\Passwordless\Ramsey\Uuid\Math\RoundingMode::HALF_EVEN => \Akeeba\Passwordless\Brick\Math\RoundingMode::HALF_EVEN,
    ];

    public function add(\Akeeba\Passwordless\Ramsey\Uuid\Type\NumberInterface $augend, \Akeeba\Passwordless\Ramsey\Uuid\Type\NumberInterface ...$addends): \Akeeba\Passwordless\Ramsey\Uuid\Type\NumberInterface
    {
        $sum = \Akeeba\Passwordless\Brick\Math\BigInteger::of($augend->toString());

        foreach ($addends as $addend) {
            $sum = $sum->plus($addend->toString());
        }

        return new \Akeeba\Passwordless\Ramsey\Uuid\Type\Integer((string) $sum);
    }

    public function subtract(\Akeeba\Passwordless\Ramsey\Uuid\Type\NumberInterface $minuend, \Akeeba\Passwordless\Ramsey\Uuid\Type\NumberInterface ...$subtrahends): \Akeeba\Passwordless\Ramsey\Uuid\Type\NumberInterface
    {
        $difference = \Akeeba\Passwordless\Brick\Math\BigInteger::of($minuend->toString());

        foreach ($subtrahends as $subtrahend) {
            $difference = $difference->minus($subtrahend->toString());
        }

        return new \Akeeba\Passwordless\Ramsey\Uuid\Type\Integer((string) $difference);
    }

    public function multiply(\Akeeba\Passwordless\Ramsey\Uuid\Type\NumberInterface $multiplicand, \Akeeba\Passwordless\Ramsey\Uuid\Type\NumberInterface ...$multipliers): \Akeeba\Passwordless\Ramsey\Uuid\Type\NumberInterface
    {
        $product = \Akeeba\Passwordless\Brick\Math\BigInteger::of($multiplicand->toString());

        foreach ($multipliers as $multiplier) {
            $product = $product->multipliedBy($multiplier->toString());
        }

        return new \Akeeba\Passwordless\Ramsey\Uuid\Type\Integer((string) $product);
    }

    public function divide(
        int $roundingMode,
        int $scale,
        \Akeeba\Passwordless\Ramsey\Uuid\Type\NumberInterface $dividend,
        \Akeeba\Passwordless\Ramsey\Uuid\Type\NumberInterface ...$divisors
    ): \Akeeba\Passwordless\Ramsey\Uuid\Type\NumberInterface {
        $brickRounding = $this->getBrickRoundingMode($roundingMode);

        $quotient = \Akeeba\Passwordless\Brick\Math\BigDecimal::of($dividend->toString());

        foreach ($divisors as $divisor) {
            $quotient = $quotient->dividedBy($divisor->toString(), $scale, $brickRounding);
        }

        if ($scale === 0) {
            return new \Akeeba\Passwordless\Ramsey\Uuid\Type\Integer((string) $quotient->toBigInteger());
        }

        return new \Akeeba\Passwordless\Ramsey\Uuid\Type\Decimal((string) $quotient);
    }

    public function fromBase(string $value, int $base): \Akeeba\Passwordless\Ramsey\Uuid\Type\Integer
    {
        try {
            return new \Akeeba\Passwordless\Ramsey\Uuid\Type\Integer((string) \Akeeba\Passwordless\Brick\Math\BigInteger::fromBase($value, $base));
        } catch (\Akeeba\Passwordless\Brick\Math\Exception\MathException | \InvalidArgumentException $exception) {
            throw new \Akeeba\Passwordless\Ramsey\Uuid\Exception\InvalidArgumentException(
                $exception->getMessage(),
                (int) $exception->getCode(),
                $exception
            );
        }
    }

    public function toBase(\Akeeba\Passwordless\Ramsey\Uuid\Type\Integer $value, int $base): string
    {
        try {
            return \Akeeba\Passwordless\Brick\Math\BigInteger::of($value->toString())->toBase($base);
        } catch (\Akeeba\Passwordless\Brick\Math\Exception\MathException | \InvalidArgumentException $exception) {
            throw new \Akeeba\Passwordless\Ramsey\Uuid\Exception\InvalidArgumentException(
                $exception->getMessage(),
                (int) $exception->getCode(),
                $exception
            );
        }
    }

    public function toHexadecimal(\Akeeba\Passwordless\Ramsey\Uuid\Type\Integer $value): \Akeeba\Passwordless\Ramsey\Uuid\Type\Hexadecimal
    {
        return new \Akeeba\Passwordless\Ramsey\Uuid\Type\Hexadecimal($this->toBase($value, 16));
    }

    public function toInteger(\Akeeba\Passwordless\Ramsey\Uuid\Type\Hexadecimal $value): \Akeeba\Passwordless\Ramsey\Uuid\Type\Integer
    {
        return $this->fromBase($value->toString(), 16);
    }

    /**
     * Maps ramsey/uuid rounding modes to those used by brick/math
     */
    private function getBrickRoundingMode(int $roundingMode): int
    {
        return self::ROUNDING_MODE_MAP[$roundingMode] ?? 0;
    }
}
