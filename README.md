# Akeeba Passwordless Login

A W3C Webauthn passwordless login solution for Joomla!

## What does it do?

This plugin implements W3C Web Authentication (WebAuthn) in Joomla 3 and 4. It allows you to log into a site without using a password.
 
WebAuthn allows users to authenticate (log in) securely into a site without using a password. Instead, it uses _authenticators_. An authenticator is either a discrete hardware device or a piece of secure hardware (e.g. TPM or Secure Enclave) built into your device. Moreover, it only works under HTTPS. By using secure hardware and secure transport it makes sure that the authentication is resistant to eavesdropping, phishing, brute-force and other attack modes associated with fixed passwords.

Before using this plugin please take a minute to [learn more about WebAuthn and play with it in your browser](https://webauthn.io).

## License

This plugin is licensed under the [GNU General Public License, version 3 of the license](https://www.gnu.org/licenses/gpl-3.0.en.html) or (at your option) any later version published by the Free Software Foundation.

## History

We wrote this plugin for Joomla 3 when WebAuthn became a W3C standard, before WebAuthn was supported by most major browsers. Shortly after we added Joomla 4 support as well.

We contributed this as a feature to Joomla 4 in early 2020. However, this required rewriting the plugin and its JavaScript in a way that is incompatible with Joomla 3.

This repository contains the parallel development of our plugin for Joomla 3 _and_ 4. It stated goal is to support Joomla 3 until Joomla 3 reaches its end of life. It will also support Joomla 4, even though Joomla 4 already has a passwordless login feature. The idea is that we can develop this plugin without the contraints of what can be accepted in the Joomla core. We can explore new features which may or may not end up in Joomla itself.    

In an effort to avoid conflicts with Joomla 4, we renamed this plugin from plg_system_webauthn (which is now the name of the Joomla 4 core plugin) to plg_system_passwordless.

## Download

This plugin is currently under active development. There are no public downloads.

## Minimum requirements

Joomla 3.9, 3.10 or 4.0.

For PHP minimum version requirement please consult [the composer.json file](composer.json).

MySQL (including compatible servers such as MariaDB) and PostgreSQL are supported but we only test our software with MySQL.

You will obviously need a modern web browser with Web Authentication support and JavaScript enabled to use this plugin.

## Support

Please consult [the Support Policy page](.github/SUPPORT.md). 
 
## For developers

### Build requirements

In order to build the installation packages of this component you will need to have the following tools:

* A command line environment. Using Bash under Linux / Mac OS X works best.
* A PHP CLI binary in your path
* Phing installed account-wide on your machine
* Command line Git executables

You will also need the following path structure inside a folder on your system

* **webauthn** This repository
* **buildfiles** [Akeeba Build Tools](https://github.com/akeeba/buildfiles)

You will need to use the exact folder names specified here.

### Useful Phing tasks

All commands are to be run from the `build` directory of this repository.

Create a dev release installation package

	phing git
		
The installable ZIP file will appear in the `release` directory inside the repository's root.
