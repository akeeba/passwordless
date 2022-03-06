# Akeeba Passwordless Login

A W3C Webauthn passwordless login solution for Joomla!

## What does it do?

This plugin implements W3C Web Authentication (WebAuthn) in Joomla  4. It allows you to log into a site without using a password.
 
WebAuthn allows users to authenticate (log in) securely into a site without using a password. Instead, it uses _authenticators_. An authenticator is either a discrete hardware device or a piece of secure hardware (e.g. TPM or Secure Enclave) built into your device. Moreover, it only works under HTTPS. By using secure hardware and secure transport it makes sure that the authentication is resistant to eavesdropping, phishing, brute-force and other attack modes associated with fixed passwords.

Before using this plugin please take a minute to [learn more about WebAuthn and play with it in your browser](https://webauthn.io).

## License

This plugin is licensed under the [GNU General Public License, version 3 of the license](https://www.gnu.org/licenses/gpl-3.0.en.html) or (at your option) any later version published by the Free Software Foundation.

## Download

Check out the Releases section of this GitHub repository.

## Minimum requirements

Joomla 4.0.

For PHP minimum version requirement please consult [the composer.json file](composer.json).

MySQL (including compatible servers such as MariaDB) and PostgreSQL are supported but we only test our software with MySQL.

You will need a modern web browser with Web Authentication support and JavaScript enabled to use this plugin.

## Support

Please consult [the “Support philosophy” page](.github/SUPPORT.md). 

## History

I wrote this plugin for Joomla 3 when WebAuthn became a W3C standard, before WebAuthn was supported by most major browsers. Shortly after I added Joomla 4 support as well. I contributed WebAuthn passwordless authentication to Joomla 4 in early 2020.

This repository contains the parallel development of this plugin for 4. We can develop this plugin without the constraints of what can be accepted in the Joomla core and when. As a result we can explore new features which wouldn't make it to Joomla in a reasonable amount of time.

In an effort to avoid conflicts with Joomla 4, we renamed this plugin from plg_system_webauthn (which is now the name of the Joomla 4 core plugin) to plg_system_passwordless.

Most notably, this plugin remembers the last user logged into the site. As a result, the next login attempt does not require entering the username, just clicking on the login button. Completely frictionless and perfectly secure.   
 
## For developers

### Quick'n'dirty installation

You need to have `composer` and `npm` installed globally. These are the same requirements for building Joomla 4.

From the root of this repository install the dependencies:
```shell script
composer install
npm install
```

You can ZIP the `plugins/system/passwordless` folder to create a plugin installation file, e.g. from the repository's root:
```shell script
pushd plugins/system/passwordless
zip -r ../../../release/plg_system_passwordless.zip *
popd
```

If you have modified the `plugins/system/passwordless/media/js/passwordless.js` file you will need to run
```shell script
npm run build
```
before creating the installation ZIP package.