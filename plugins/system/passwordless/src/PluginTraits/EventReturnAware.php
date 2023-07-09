<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Plugin\System\Passwordless\PluginTraits;

defined('_JEXEC') or die();

use Joomla\Event\Event;

trait EventReturnAware
{
	/**
	 * Adds a result value to an event
	 *
	 * @param   Event   $event  The event we were processing
	 * @param   mixed   $value  The value to append to the event's results
	 *
	 * @return  void
	 */
	private function returnFromEvent(Event $event, $value = null): void
	{
		$result = $event->getArgument('result') ?: [];

		if (!is_array($result))
		{
			$result = [$result];
		}

		$result[] = $value;

		$event->setArgument('result', $result);
	}
}