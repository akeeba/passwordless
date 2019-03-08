/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

// TODO Write the akeeba_passwordless_login() function
// See https://github.com/web-auth/webauthn-framework/blob/v1.0/doc/webauthn/PublicKeyCredentialRequest.md

function akeeba_passwordless_login(that, callback_url)
{
    function findNamedField(elForm, fieldName)
    {
        let elInputs = elForm.querySelectorAll("input");

        if (!elInputs.length)
        {
            return null;
        }

        for (var i = 0; i < elInputs.length; i++)
        {
            var elInput = elInputs[i];

            if (elInput.name === fieldName)
            {
                return elInput;
            }
        }

        return null;
    }

    function trawlParentElements(innerElement, fieldName)
    {
        var elElement = innerElement.parentElement;
        var elInput   = null;

        while (true)
        {
            if (elElement.nodeName === "FORM")
            {
                elInput = findNamedField(elElement, fieldName);

                if (elInput !== null)
                {
                    return elInput;
                }

                break;
            }

            var elForms = elElement.querySelectorAll("form");

            if (elForms.length)
            {
                for (var i = 0; i < elForms.length; i++)
                {
                    elInput = findNamedField(elForms[i], fieldName);

                    if (elInput !== null)
                    {
                        return elInput;
                    }
                }
            }

            if (!elElement.parentElement)
            {
                break;
            }

            elElement = elElement.parentElement;
        }

        return null;
    }

    // Get the username
    let elUsername = trawlParentElements(that, "username");
    let elReturn   = trawlParentElements(that, "return");

    if (elUsername === null)
    {
        alert(Joomla.JText._("PLG_SYSTEM_WEBAUTHN_ERR_CANNOT_FIND_USERNAME"));

        return false;
    }

    let username  = elUsername.value;
    let returnUrl = elReturn ? elReturn.value : null;

    // No username? We cannot proceed. We need a username to find the acceptable public keys :(
    if (username === "")
    {
        alert(Joomla.JText._("PLG_SYSTEM_WEBAUTHN_ERR_EMPTY_USERNAME"));

        return false;
    }

    // Get the Public Key Credential Request Options (challenge and acceptable public keys)
    let postBackData = {
        "option":    "com_ajax",
        "group":     "system",
        "plugin":    "webauthn",
        "format":    "raw",
        "akaction":  "challenge",
        "encoding":  "raw",
        "username":  username,
        "returnUrl": returnUrl,
    };

    window.jQuery.ajax({
        type:     "POST",
        url:      callback_url,
        data:     postBackData,
        dataType: "json"
    })
        .done(function (jsonData) {
            akeeba_passwordless_handle_login_challenge(jsonData, callback_url);
        })
        .fail(function (error) {
            akeeba_passwordless_handle_login_error(error.status + " " + error.statusText);
        })


}

function akeeba_passwordless_handle_login_challenge(publicKey, callback_url)
{
    function arrayToBase64String(a)
    {
        return btoa(String.fromCharCode(...a));
    }

    if (!publicKey.challenge)
    {
        akeeba_passwordless_handle_login_error(Joomla.JText._('PLG_SYSTEM_WEBAUTHN_ERR_INVALID_USERNAME'));

        return;
    }

    publicKey.challenge        = Uint8Array.from(window.atob(publicKey.challenge), c => c.charCodeAt(0));
    publicKey.allowCredentials = publicKey.allowCredentials.map(function (data) {
        return {
            ...data,
            "id": Uint8Array.from(atob(data.id), c => c.charCodeAt(0))
        };
    });

    navigator.credentials.get({publicKey})
        .then(data => {
            let publicKeyCredential = {
                id:       data.id,
                type:     data.type,
                rawId:    arrayToBase64String(new Uint8Array(data.rawId)),
                response: {
                    authenticatorData: arrayToBase64String(new Uint8Array(data.response.authenticatorData)),
                    clientDataJSON:    arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
                    signature:         arrayToBase64String(new Uint8Array(data.response.signature)),
                    userHandle:        data.response.userHandle ? arrayToBase64String(
                        new Uint8Array(data.response.userHandle)) : null
                }
            };

            window.location = callback_url + '&option=com_ajax&group=system&plugin=webauthn&format=raw&akaction=login&encoding=redirect&data=' +
                btoa(JSON.stringify(publicKeyCredential));

        }, error => {
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
function akeeba_passwordless_handle_login_error(message)
{
    alert(message);

    console.log(message);
}
