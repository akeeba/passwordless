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

namespace Akeeba\Passwordless\Ramsey\Uuid\Converter\Time;

use Akeeba\Passwordless\Ramsey\Uuid\Converter\TimeConverterInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Math\BrickMathCalculator;
use Akeeba\Passwordless\Ramsey\Uuid\Type\Hexadecimal;
use Akeeba\Passwordless\Ramsey\Uuid\Type\Time;

/**
 * Previously used to integrate moontoast/math as a bignum arithmetic library,
 * BigNumberTimeConverter is deprecated in favor of GenericTimeConverter
 *
 * @deprecated Transition to {@see GenericTimeConverter}.
 *
 * @psalm-immutable
 */
class BigNumberTimeConverter implements \Akeeba\Passwordless\Ramsey\Uuid\Converter\TimeConverterInterface
{
    /**
     * @var TimeConverterInterface
     */
    private $converter;

    public function __construct()
    {
        $this->converter = new \Akeeba\Passwordless\Ramsey\Uuid\Converter\Time\GenericTimeConverter(new \Akeeba\Passwordless\Ramsey\Uuid\Math\BrickMathCalculator());
    }

    public function calculateTime(string $seconds, string $microseconds): \Akeeba\Passwordless\Ramsey\Uuid\Type\Hexadecimal
    {
        return $this->converter->calculateTime($seconds, $microseconds);
    }

    public function convertTime(\Akeeba\Passwordless\Ramsey\Uuid\Type\Hexadecimal $uuidTimestamp): \Akeeba\Passwordless\Ramsey\Uuid\Type\Time
    {
        return $this->converter->convertTime($uuidTimestamp);
    }
}
