<?php
declare(strict_types=1);

defined('__RECTOR_RUNNING__') or die;

use Rector\Core\Configuration\Option;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Rector\Renaming\Rector\Namespace_\RenameNamespaceRector;

return static function (\Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator $containerConfigurator): void {
	// get parameters
	$parameters = $containerConfigurator->parameters();
	$parameters->set(Option::PATHS, [
		__DIR__ . '/vendor/autoload.php',
		__DIR__ . '/vendor/composer',

		__DIR__ . '/vendor/beberlei',
		__DIR__ . '/vendor/brick',
		__DIR__ . '/vendor/fgrosse',
		__DIR__ . '/vendor/league',
		__DIR__ . '/vendor/ramsey',
		__DIR__ . '/vendor/spomky-labs',
		__DIR__ . '/vendor/symfony',
		__DIR__ . '/vendor/thecodingmachine',
		__DIR__ . '/vendor/web-auth',
	]);
//	$parameters->set(Option::SKIP, [
//		__DIR__ . '/vendor/foo.bar',
//	]);

	// get services (needed for register a single rule)
	$services = $containerConfigurator->services();

	// register a single rule
	$services->set(Rector\Renaming\Rector\Namespace_\RenameNamespaceRector::class)
		->configure([
			'Assert'        => 'Akeeba\Passwordless\Assert',
			'Brick'         => 'Akeeba\Passwordless\Brick',
			'FG'            => 'Akeeba\Passwordless\FG',
			'League'        => 'Akeeba\Passwordless\League',
			'ParagonIE'     => 'Akeeba\Passwordless\ParagonIE',
			'bcmath_compat' => 'Akeeba\Passwordless\bcmath_compat',
			'phpseclib3'    => 'Akeeba\Passwordless\phpseclib3',
			'Ramsey'        => 'Akeeba\Passwordless\Ramsey',
			'Base64Url'     => 'Akeeba\Passwordless\Base64Url',
			'CBOR'          => 'Akeeba\Passwordless\CBOR',
			'Symfony'       => 'Akeeba\Passwordless\Symfony',
			'Safe'          => 'Akeeba\Passwordless\Safe',
			'Cose'          => 'Akeeba\Passwordless\Cose',
			'Webauthn'      => 'Akeeba\Passwordless\Webauthn',
		]);
};
