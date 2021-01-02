<?php
/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2021 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

namespace Akeeba\Passwordless\Exception;

// Protect from unauthorized access
defined('_JEXEC') or die();

use RuntimeException;

class AjaxNonCmsAppException extends RuntimeException
{

}