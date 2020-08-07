/**
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

function akeeba_passwordless_arrayToBase64String(a)
{
    return btoa(String.fromCharCode.apply(String, a));
}

function akeeba_passwordless_object_merge()
{
    var ret = {};

    for (var i = 0; i < arguments.length; i++)
    {
        var source = arguments[i] != null ? arguments[i] : {};

        for (var prop in source)
        {
            if (!source.hasOwnProperty(prop))
            {
                continue;
            }

            ret[prop] = source[prop];
        }
    }

    return ret;
}

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
    if (!("credentials" in navigator))
    {
        alert(Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_NO_BROWSER_SUPPORT"));

        console.log("This browser does not support Webauthn");
        return;
    }

    // Extract the configuration from the store
    var elStore = document.getElementById(store_id);

    if (!elStore)
    {
        return;
    }

    var publicKey = JSON.parse(atob(elStore.dataset.public_key));
    var post_url  = atob(elStore.dataset.postback_url);

    // Convert the public key information to a format usable by the browser's credentials managemer
    var fixedChallenge  = publicKey.challenge.replace(/-/g, "+").replace(/_/g, "/");
    publicKey.challenge = Uint8Array.from(window.atob(fixedChallenge), function (c) {
        return c.charCodeAt(0);
    });
    publicKey.user.id   = Uint8Array.from(window.atob(publicKey.user.id), function (c) {
        return c.charCodeAt(0);
    });

    if (publicKey.excludeCredentials)
    {
        publicKey.excludeCredentials = publicKey.excludeCredentials.map(function (data) {
            return akeeba_passwordless_object_merge(data, {
                "id": Uint8Array.from(window.atob(data.id), function (c) {
                    return c.charCodeAt(0);
                })
            });
        });
    }

    // Ask the browser to prompt the user for their authenticator
    navigator.credentials.create({
        publicKey: publicKey
    })
        .then(function (data) {
            var publicKeyCredential = {
                id:       data.id,
                type:     data.type,
                rawId:    akeeba_passwordless_arrayToBase64String(new Uint8Array(data.rawId)),
                response: {
                    clientDataJSON:    akeeba_passwordless_arrayToBase64String(
                        new Uint8Array(data.response.clientDataJSON)),
                    attestationObject: akeeba_passwordless_arrayToBase64String(
                        new Uint8Array(data.response.attestationObject))
                }
            };

            var postBackData = {
                "option":   "com_ajax",
                "group":    "system",
                "plugin":   "passwordless",
                "format":   "raw",
                "akaction": "create",
                "encoding": "raw",
                "data":     btoa(JSON.stringify(publicKeyCredential))
            };

            window.jQuery.post(post_url, postBackData)
                .done(function (responseHTML) {
                    var elements = document.querySelectorAll(interface_selector);

                    if (!elements)
                    {
                        return;
                    }

                    var elContainer = elements[0];

                    elContainer.outerHTML = responseHTML;
                })
                .fail(function (data) {
                    akeeba_passwordless_handle_creation_error(data.status + " " + data.statusText);
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

/**
 * Edit label button
 *
 * @param   {Element} that      The button being clicked
 * @param   {String}  store_id  CSS ID for the element storing the configuration in its data properties
 */
function akeeba_passwordless_edit_label(that, store_id)
{
    // Extract the configuration from the store
    var elStore = document.getElementById(store_id);

    if (!elStore)
    {
        return;
    }

    var post_url = atob(elStore.dataset.postback_url);

    // Find the UI elements
    var elTR         = that.parentElement.parentElement;
    var credentialId = elTR.dataset.credential_id;
    var elTDs        = elTR.querySelectorAll("td");
    var elLabelTD    = elTDs[0];
    var elButtonsTD  = elTDs[1];
    var elButtons    = elButtonsTD.querySelectorAll("button");
    var elEdit       = elButtons[0];
    var elDelete     = elButtons[1];

    // Show the editor
    var oldLabel = elLabelTD.innerText;

    var elInput          = document.createElement("input");
    elInput.type         = "text";
    elInput.name         = "label";
    elInput.defaultValue = oldLabel;

    var elSave       = document.createElement("button");
    elSave.className = "akpwl-btn--green--small";
    elSave.innerText = Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_SAVE_LABEL");
    elSave.addEventListener("click", function (e) {
        var elNewLabel = elInput.value;

        if (elNewLabel !== "")
        {
            var postBackData = {
                "option":        "com_ajax",
                "group":         "system",
                "plugin":        "passwordless",
                "format":        "json",
                "encoding":      "json",
                "akaction":      "savelabel",
                "credential_id": credentialId,
                "new_label":     elNewLabel
            };

            window.jQuery.post(post_url, postBackData)
                .done(function (result) {
                    if ((result !== true) && (result !== "true"))
                    {
                        akeeba_passwordless_handle_creation_error(
                            Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_LABEL_NOT_SAVED"));

                        return;
                    }

                    //alert(Joomla.JText._('PLG_SYSTEM_PASSWORDLESS_MSG_SAVED_LABEL'));
                })
                .fail(function (data) {
                    akeeba_passwordless_handle_creation_error(Joomla.JText._(
                        "PLG_SYSTEM_PASSWORDLESS_ERR_LABEL_NOT_SAVED") + " -- " + data.status + " " + data.statusText);
                });
        }

        elLabelTD.innerText = elNewLabel;
        elEdit.disabled     = false;
        elDelete.disabled   = false;

        return false;
    }, false);

    var elCancel       = document.createElement("button");
    elCancel.className = "akpwl-btn--red--small";
    elCancel.innerText = Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_CANCEL_LABEL");
    elCancel.addEventListener("click", function (e) {
        elLabelTD.innerText = oldLabel;
        elEdit.disabled     = false;
        elDelete.disabled   = false;

        return false;
    }, false);

    elLabelTD.innerHTML = "";
    elLabelTD.appendChild(elInput);
    elLabelTD.appendChild(elSave);
    elLabelTD.appendChild(elCancel);
    elEdit.disabled   = true;
    elDelete.disabled = true;

    return false;
}

/**
 * Delete button
 *
 * @param   {Element} that      The button being clicked
 * @param   {String}  store_id  CSS ID for the element storing the configuration in its data properties
 */
function akeeba_passwordless_delete(that, store_id)
{
    // Extract the configuration from the store
    var elStore = document.getElementById(store_id);

    if (!elStore)
    {
        return;
    }

    var post_url = atob(elStore.dataset.postback_url);

    // Find the UI elements
    var elTR         = that.parentElement.parentElement;
    var credentialId = elTR.dataset.credential_id;
    var elTDs        = elTR.querySelectorAll("td");
    var elButtonsTD  = elTDs[1];
    var elButtons    = elButtonsTD.querySelectorAll("button");
    var elEdit       = elButtons[0];
    var elDelete     = elButtons[1];

    elEdit.disabled   = true;
    elDelete.disabled = true;

    // Delete the record
    var postBackData = {
        "option":        "com_ajax",
        "group":         "system",
        "plugin":        "passwordless",
        "format":        "json",
        "encoding":      "json",
        "akaction":      "delete",
        "credential_id": credentialId,
    };

    window.jQuery.post(post_url, postBackData)
        .done(function (result) {
            if ((result !== true) && (result !== "true"))
            {
                elEdit.disabled   = false;
                elDelete.disabled = false;

                akeeba_passwordless_handle_creation_error(Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_NOT_DELETED"));

                return;
            }

            elTR.parentElement.removeChild(elTR);

            //alert(Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_MSG_DELETED"));
        })
        .fail(function (data) {
            elEdit.disabled   = false;
            elDelete.disabled = false;

            akeeba_passwordless_handle_creation_error(
                Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_NOT_DELETED") + " -- " + data.status + " " + data.statusText);
        });

    return false;
}