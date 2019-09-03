# Akeeba Passwordless Login

A W3C Webauthn passwordless login solution for Joomla!

# What does it do?

This plugin implements W3C Web Authentication (WebAuthn) in Joomla. It is licensed under the [GNU General Public License, version 3 of the license](https://www.gnu.org/licenses/gpl-3.0.en.html) or (at your option) any later version published by the Free Software Foundation.

WebAuthn allows users to authenticate (log in) securely into a site without using a password. Instead it uses _authenticators_. An authenticator is either a discrete hardware device or a piece of secure hardware (e.g. TPM or Secure Enclave) built into your device. Moreover, it only works under HTTPS. By using secure hardware and secure transport it makes sure that the authentication is resistant to eavesdropping, phishing, brute-force and other attack modes associated with fixed passwords.

Before using this plugin please take a minute to [learn more about WebAuthn and play with it](https://webauthn.io).

**Please note that you STILL need to provide your _username_. WebAuthn in its current form only replaces your _password_.** That is to say, _browsers themselves_ do not allow us to get rid of the username.

# Download

Pre-built packages of Akeeba PasswordLess Login are available through [our GitHub repository's Releases page](https://github.com/akeeba/passwordless/releases).

Akeeba Passwordless Login comes with English (Great Britain) language built-in. We do not offer official translations for any other language nor will we accept pull requests for language files. You are welcome to translate to your own language and make the translation available free of charge under the GPLv3 license which the original translation files are licensed under.

# Minimum requirements

Please consult [the Requirements documentation page](https://github.com/akeeba/passwordless/wiki/Requirements).

# Support

Please consult [the Support Policy page](https://github.com/akeeba/passwordless/wiki/Support-Policy). Any GitHub issues not adhering to the policy and unsolicited support requests sent through any medium will receive no reply at all.
 
# For developers

## Build requirements

In order to build the installation packages of this component you will need to have the following tools:

* A command line environment. Using Bash under Linux / Mac OS X works best.
* A PHP CLI binary in your path
* Phing installed account-wide on your machine
* Command line Git executables

You will also need the following path structure inside a folder on your system

* **webauthn** This repository
* **buildfiles** [Akeeba Build Tools](https://github.com/akeeba/buildfiles)

You will need to use the exact folder names specified here.

## Useful Phing tasks

All commands are to be run from the `build` directory of this repository.

Create a dev release installation package

		phing git
		
The installable ZIP file is written in the `release` directory inside the repository's root.