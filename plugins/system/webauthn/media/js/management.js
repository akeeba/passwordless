/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

/**
 * Ask the user to link an authenticator using the provided public key (created server-side). Posts the credentials to
 * the URL defined in post_url using AJAX. That URL must re-render the management interface. These contents will replace
 * the element identified by the interface_selector CSS selector.
 *
 * @param   {String}  store_id            CSS ID for the element storing the configuration in its data properties
 * @param   {String}  interface_selector  CSS selector for the GUI container
 */
function akeeba_passwordless_create_credentials(store_id, interface_selector)
{
    // Make sure the browser supports Webauthn
    if (!('credentials' in navigator)) {
        alert(Joomla.JText._('PLG_SYSTEM_WEBAUTHN_ERR_NO_BROWSER_SUPPORT'))

        console.log("This browser does not support Webauthn");
        return;
    }

    // Extract the configuration from the store
    let elStore = document.getElementById(store_id);

    if (!elStore)
    {
        return;
    }

    let publicKey = JSON.parse(atob(elStore.dataset.public_key));
    let post_url  = atob(elStore.dataset.postback_url);

    // Utility function to convert array data to base64 strings
    function arrayToBase64String(a)
    {
        return btoa(String.fromCharCode(...a));
    }

    // Convert the public key infomration to a format usable by the browser's credentials managemer
    publicKey.challenge = Uint8Array.from(window.atob(publicKey.challenge), c => c.charCodeAt(0));
    publicKey.user.id   = Uint8Array.from(window.atob(publicKey.user.id), c => c.charCodeAt(0));

    if (publicKey.excludeCredentials)
    {
        publicKey.excludeCredentials = publicKey.excludeCredentials.map(function (data) {
            return {
                ...data,
                "id": Uint8Array.from(window.atob(data.id), c => c.charCodeAt(0))
            };
        });
    }

    // Ask the browser to prompt the user for their authenticator
    navigator.credentials.create({publicKey})
        .then(function (data) {
            let publicKeyCredential = {
                id:       data.id,
                type:     data.type,
                rawId:    arrayToBase64String(new Uint8Array(data.rawId)),
                response: {
                    clientDataJSON:    arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
                    attestationObject: arrayToBase64String(new Uint8Array(data.response.attestationObject))
                }
            };

            let postBackData = {
                "option":   "com_ajax",
                "group":    "system",
                "plugin":   "webauthn",
                "format":   "raw",
                "akaction": "create",
                "encoding": "raw",
                "data":     btoa(JSON.stringify(publicKeyCredential))
            };

            window.jQuery.post(post_url, postBackData)
                .done(function (responseHTML) {
                    let elements = document.querySelectorAll(interface_selector);

                    if (!elements)
                    {
                        return;
                    }

                    let elContainer = elements[0];

                    elContainer.outerHTML = responseHTML;
                })
                .fail(function (data) {
                    akeeba_passwordless_handle_creation_error(data.status + ' ' + data.statusText);
                });


        }, function (error) {
            // An error occurred: timeout, request to provide the authenticator refused, hardware / software error...
            akeeba_passwordless_handle_creation_error(error);
        });
}

/**
 * A simple error handler
 *
 * @param   {String}  message
 */
function akeeba_passwordless_handle_creation_error(message)
{
    alert(message);

    console.log(message);
}