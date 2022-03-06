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

namespace Akeeba\Passwordless\Ramsey\Uuid\Generator;

use Akeeba\Passwordless\Ramsey\Uuid\Converter\TimeConverterInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Provider\NodeProviderInterface;
use Akeeba\Passwordless\Ramsey\Uuid\Provider\TimeProviderInterface;

/**
 * TimeGeneratorFactory retrieves a default time generator, based on the
 * environment
 */
class TimeGeneratorFactory
{
    /**
     * @var NodeProviderInterface
     */
    private $nodeProvider;

    /**
     * @var TimeConverterInterface
     */
    private $timeConverter;

    /**
     * @var TimeProviderInterface
     */
    private $timeProvider;

    public function __construct(
        \Akeeba\Passwordless\Ramsey\Uuid\Provider\NodeProviderInterface $nodeProvider,
        \Akeeba\Passwordless\Ramsey\Uuid\Converter\TimeConverterInterface $timeConverter,
        \Akeeba\Passwordless\Ramsey\Uuid\Provider\TimeProviderInterface $timeProvider
    ) {
        $this->nodeProvider = $nodeProvider;
        $this->timeConverter = $timeConverter;
        $this->timeProvider = $timeProvider;
    }

    /**
     * Returns a default time generator, based on the current environment
     */
    public function getGenerator(): \Akeeba\Passwordless\Ramsey\Uuid\Generator\TimeGeneratorInterface
    {
        return new \Akeeba\Passwordless\Ramsey\Uuid\Generator\DefaultTimeGenerator(
            $this->nodeProvider,
            $this->timeConverter,
            $this->timeProvider
        );
    }
}
