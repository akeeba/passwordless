<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2022 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Plugin\System\Passwordless\Exception;

// Protect from unauthorized access
defined('_JEXEC') or die();

use RuntimeException;

class AjaxNonCmsAppException extends RuntimeException
{

}