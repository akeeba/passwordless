<?php
$renamedNamespaces = [
//	'Assert'        => 'Akeeba\Passwordless\Assert',
//	'FG'            => 'Akeeba\Passwordless\FG',
//	'Base64Url'     => 'Akeeba\Passwordless\Base64Url',
//	'Symfony'       => 'Akeeba\Passwordless\Symfony',

	'Brick'         => 'Akeeba\Passwordless\Brick',
	'League'        => 'Akeeba\Passwordless\League',
	'ParagonIE'     => 'Akeeba\Passwordless\ParagonIE',
	'bcmath_compat' => 'Akeeba\Passwordless\bcmath_compat',
	'phpseclib3'    => 'Akeeba\Passwordless\phpseclib3',
	'Ramsey'        => 'Akeeba\Passwordless\Ramsey',
	'CBOR'          => 'Akeeba\Passwordless\CBOR',
	'Safe'          => 'Akeeba\Passwordless\Safe',
	'Cose'          => 'Akeeba\Passwordless\Cose',
	'Webauthn'      => 'Akeeba\Passwordless\Webauthn',
];

$editStack = [
	// Replace changed namespaces
	function (string $contents) use ($renamedNamespaces): string {
		$findThis = array_map(function ($x) {
			return "'" . str_replace('\\', '\\\\', rtrim($x, '\\')) . '\\';
		}, array_keys($renamedNamespaces));
		$changeTo = array_map(function ($x) {
			return "'" . str_replace('\\', '\\\\', rtrim($x, '\\')) . '\\';
		}, array_values($renamedNamespaces));

		return str_replace($findThis, $changeTo, $contents);
	},
	// Never use the static loader (it's invalid after running Rector and I don't fancy creating it afresh)
	function (string $contents): string {
		return str_replace('$useStaticLoader = ', '$useStaticLoader = false && ', $contents);
	},
];

foreach ([
	         __DIR__ . '/vendor/composer/autoload_classmap.php',
	         __DIR__ . '/vendor/composer/autoload_files.php',
	         __DIR__ . '/vendor/composer/autoload_namespaces.php',
	         __DIR__ . '/vendor/composer/autoload_psr4.php',
	         __DIR__ . '/vendor/composer/autoload_real.php',
         ] as $composerFileToEdit)
{
	$contents = file_get_contents($composerFileToEdit);
	$oldSig   = sha1($contents);

	foreach ($editStack as $callback)
	{
		$contents = $callback($contents);
	}

	$newSig = sha1($contents);

	if ($newSig === $oldSig)
	{
		continue;
	}

	file_put_contents($composerFileToEdit, $contents);
}
