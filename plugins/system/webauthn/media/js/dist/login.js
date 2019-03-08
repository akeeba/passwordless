"use strict";

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; var ownKeys = Object.keys(source); if (typeof Object.getOwnPropertySymbols === 'function') { ownKeys = ownKeys.concat(Object.getOwnPropertySymbols(source).filter(function (sym) { return Object.getOwnPropertyDescriptor(source, sym).enumerable; })); } ownKeys.forEach(function (key) { _defineProperty(target, key, source[key]); }); } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function _toConsumableArray(arr) { return _arrayWithoutHoles(arr) || _iterableToArray(arr) || _nonIterableSpread(); }

function _nonIterableSpread() { throw new TypeError("Invalid attempt to spread non-iterable instance"); }

function _iterableToArray(iter) { if (Symbol.iterator in Object(iter) || Object.prototype.toString.call(iter) === "[object Arguments]") return Array.from(iter); }

function _arrayWithoutHoles(arr) { if (Array.isArray(arr)) { for (var i = 0, arr2 = new Array(arr.length); i < arr.length; i++) { arr2[i] = arr[i]; } return arr2; } }

/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */
// TODO Write the akeeba_passwordless_login() function
// See https://github.com/web-auth/webauthn-framework/blob/v1.0/doc/webauthn/PublicKeyCredentialRequest.md
function akeeba_passwordless_login(that, callback_url) {
  function findUsernameField(elForm) {
    var elInputs = elForm.querySelectorAll("input");

    if (!elInputs.length) {
      return null;
    }

    for (var i = 0; i < elInputs.length; i++) {
      var elInput = elInputs[i];

      if (elInput.name === "username") {
        return elInput;
      }
    }

    return null;
  }

  function trawlParentElements(innerElement) {
    var elElement = innerElement.parentElement;
    var elInput = null;

    while (true) {
      if (elElement.nodeName === "FORM") {
        elInput = findUsernameField(elElement);

        if (elInput !== null) {
          return elInput;
        }

        break;
      }

      var elForms = elElement.querySelectorAll("form");

      if (elForms.length) {
        for (var i = 0; i < elForms.length; i++) {
          elInput = findUsernameField(elForms[i]);

          if (elInput !== null) {
            return elInput;
          }
        }
      }

      if (!elElement.parentElement) {
        break;
      }

      elElement = elElement.parentElement;
    }

    return null;
  } // Get the username


  var elUsername = trawlParentElements(that);

  if (elUsername === null) {
    alert(Joomla.JText._("PLG_SYSTEM_WEBAUTHN_ERR_CANNOT_FIND_USERNAME"));
    return false;
  }

  var username = elUsername.value; // No username? We cannot proceed. We need a username to find the acceptable public keys :(

  if (username === "") {
    alert(Joomla.JText._("PLG_SYSTEM_WEBAUTHN_ERR_EMPTY_USERNAME"));
    return false;
  } // Get the Public Key Credential Request Options (challenge and acceptable public keys)


  var postBackData = {
    "option": "com_ajax",
    "group": "system",
    "plugin": "webauthn",
    "format": "raw",
    "akaction": "challenge",
    "encoding": "raw",
    "username": username
  };
  window.jQuery.ajax({
    type: "POST",
    url: callback_url,
    data: postBackData,
    dataType: "json"
  }).done(function (jsonData) {
    akeeba_passwordless_handle_login_challenge(jsonData, callback_url);
  }).fail(function (error) {
    akeeba_passwordless_handle_login_error(error.status + ' ' + error.statusText);
  });
}

function akeeba_passwordless_handle_login_challenge(publicKey, callback_url) {
  function arrayToBase64String(a) {
    return btoa(String.fromCharCode.apply(String, _toConsumableArray(a)));
  }

  if (!publicKey.challenge) {
    akeeba_passwordless_handle_login_error(Joomla.JText._('PLG_SYSTEM_WEBAUTHN_ERR_INVALID_USERNAME'));
    return;
  }

  publicKey.challenge = Uint8Array.from(window.atob(publicKey.challenge), function (c) {
    return c.charCodeAt(0);
  });
  publicKey.allowCredentials = publicKey.allowCredentials.map(function (data) {
    return _objectSpread({}, data, {
      "id": Uint8Array.from(atob(data.id), function (c) {
        return c.charCodeAt(0);
      })
    });
  });
  navigator.credentials.get({
    publicKey: publicKey
  }).then(function (data) {
    var publicKeyCredential = {
      id: data.id,
      type: data.type,
      rawId: arrayToBase64String(new Uint8Array(data.rawId)),
      response: {
        authenticatorData: arrayToBase64String(new Uint8Array(data.response.authenticatorData)),
        clientDataJSON: arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
        signature: arrayToBase64String(new Uint8Array(data.response.signature)),
        userHandle: data.response.userHandle ? arrayToBase64String(new Uint8Array(data.response.userHandle)) : null
      }
    };
    window.location = callback_url + '&option=com_ajax&group=system&plugin=webauthn&format=raw&akaction=login&encoding=redirect&data=' + btoa(JSON.stringify(publicKeyCredential));
  }, function (error) {
    // Example: timeout, interaction refused...
    console.log(error);
    akeeba_passwordless_handle_login_error(error);
  });
}
/**
 * A simple error handler
 *
 * @param   {String}  message
 */


function akeeba_passwordless_handle_login_error(message) {
  alert(message);
  console.log(message);
}
//# sourceMappingURL=login.js.map