# Akeeba Passwordless Login

A W3C Webauthn passwordless login solution for Joomla!

## WORK IN PROGRESS

This repository currently represents work in progress. It has not reached a point where it's usable. DO NOT attempt to use on your site. Ignore this warning at your peril but if something breaks don't cry; you get to keep both pieces.

## What does it do?

This plugin lets users link their Joomla user accounts to one or more Webauthn passwordless authentication methods. They can then use these methods for passwordless login into the site.

In practical terms, your users can log into your site using a FIDO U2F hardware key, a FIDO2 hardware key or credentials stored in their device's Trusted Platform Module (e.g. using Windows Hello on Windows 10).

You will most likely need to create template overrides on your site to integrate passwordless authentication. This is not a magic plugin that you activate and get that feature. Joomla is built on the assumption that users always need to provide a username and password when logging in. We have to apply some workarounds to get passwordless authentication working in Joomla. 

For more information and documentation for administrators, users and developers please [consult the documentation Wiki](https://github.com/akeeba/passwordless/wiki).

## Download

Pre-built packages of Akeeba PasswordLess Login are available through [our GitHub repository's Releases page](https://github.com/akeeba/passwordless/releases).

Akeeba Passwordless Login comes with English (Great Britain) language built-in. We do not offer official translations for any other language nor will we accept pull requests for language files. You are welcome to translate to your own language and make the translation available free of charge under the GPLv3 license which the original translation files are licensed under.

## No support - For developers only

This software is provided **WITHOUT ANY KIND OF END USER SUPPORT**. You are free to consult [consult the documentation Wiki](https://github.com/akeeba/passwordless/wiki).

If you are a developer you are free to submit a pull request with your code fix, as long as there is a clear description of what was not working for you, why and how you fixed it. 
 
## Prerequisites

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
		
The installable ZIP file is written in the `release` directory inside the repository's root.