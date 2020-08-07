/*
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2020 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

window.Joomla              = window.Joomla || {};
window.akeeba              = window.akeeba || {};
window.akeeba.Passwordless = window.akeeba.Passwordless || {};

/**
 * Akeeba Passwordless Login client-side implementation
 *
 * This is the EcmaScript 6+ source of the client-side implementation. It is meant to be transpiled to ES5.1 (plain old
 * JavaScript) with Babel. The actual file being loaded can be found in dist/passwordless.js.
 */
((Joomla, Passwordless, document, window) =>
{
    "use strict";

    /**
     * Converts a simple object containing query string parameters to a single, escaped query string.
     * This method is a necessary evil since Joomla.request can only accept data as a string.
     *
     * @param    object   {object}  A plain object containing the query parameters to pass
     * @param    prefix   {string}  Prefix for array-type parameters
     *
     * @returns  {string}
     */
    const interpolateParameters = (object, prefix = "") =>
    {
        let encodedString = "";

        Object.keys(object).forEach((prop) =>
        {
            if (typeof object[prop] !== "object")
            {
                if (encodedString.length > 0)
                {
                    encodedString += "&";
                }

                if (prefix === "")
                {
                    encodedString += `${encodeURIComponent(prop)}=${encodeURIComponent(object[prop])}`;
                }
                else
                {
                    encodedString
                        += `${encodeURIComponent(prefix)}[${encodeURIComponent(prop)}]=${encodeURIComponent(
                        object[prop],
                    )}`;
                }

                return;
            }

            // Objects need special handling
            encodedString += `${interpolateParameters(object[prop], prop)}`;
        });

        return encodedString;
    };

    /**
     * Finds the first field matching a selector inside a form
     *
     * @param   {HTMLFormElement}  form           The FORM element
     * @param   {String}           fieldSelector  The CSS selector to locate the field
     *
     * @returns {Element|null}  NULL when no element is found
     */
    const findField = (form, fieldSelector) =>
    {
        const elInputs = form.querySelectorAll(fieldSelector);

        if (!elInputs.length)
        {
            return null;
        }

        return elInputs[0];
    };

    /**
     * Find a form field described by the CSS selector fieldSelector.
     * The field must be inside a <form> element which is either the
     * innerElement itself or enclosed by innerElement.
     *
     * @param   {Element}  innerElement   The element which is either our form or contains our form.
     * @param   {String}   fieldSelector  The CSS selector to locate the field
     *
     * @returns {null|Element}  NULL when no element is found
     */
    const lookForField = (innerElement, fieldSelector) =>
    {
        let elElement = innerElement.parentElement;
        let elInput   = null;

        while (true)
        {
            if (!elElement)
            {
                return null;
            }

            if (elElement.nodeName === "FORM")
            {
                elInput = lookForField(elElement, fieldSelector);

                if (elInput !== null)
                {
                    return elInput;
                }

                break;
            }

            const elForms = elElement.querySelectorAll("form");

            if (elForms.length)
            {
                for (let i = 0; i < elForms.length; i++)
                {
                    elInput = findField(elForms[i], fieldSelector);

                    if (elInput !== null)
                    {
                        return elInput;
                    }
                }

                break;
            }

            elElement = elElement.parentElement;
        }

        return null;
    };

    /**
     * A simple error handler.
     *
     * @param   {String}  message
     */
    const reportErrorToUser = (message) =>
    {
        Joomla.renderMessages({error: [message]});

        window.scrollTo({ top: 0, left: 0, behavior: 'smooth' });
    };

    /**
     * Handles the browser response for the user interaction with the authenticator. Redirects to an
     * internal page which handles the login server-side.
     *
     * @param {  Object}  publicKey     Public key request options, returned from the server
     * @param   {String}  callbackUrl  The URL we will use to post back to the server. Must include
     *   the anti-CSRF token.
     */
    const handleLoginChallenge = (publicKey, callbackUrl) =>
    {
        const arrayToBase64String = (a) => btoa(String.fromCharCode(...a));

        const base64url2base64 = (input) =>
        {
            let output = input
                .replace(/-/g, "+")
                .replace(/_/g, "/");
            const pad  = output.length % 4;
            if (pad)
            {
                if (pad === 1)
                {
                    throw new Error(
                        "InvalidLengthError: Input base64url string is the wrong length to determine padding");
                }
                output += new Array(5 - pad).join("=");
            }
            return output;
        };

        if (!publicKey.challenge)
        {
            reportErrorToUser(Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_INVALID_USERNAME"));

            return;
        }

        publicKey.challenge = Uint8Array.from(
            window.atob(base64url2base64(publicKey.challenge)), (c) => c.charCodeAt(0),
        );

        if (publicKey.allowCredentials)
        {
            publicKey.allowCredentials = publicKey.allowCredentials.map((data) =>
            {
                data.id = Uint8Array.from(window.atob(base64url2base64(data.id)), (c) => c.charCodeAt(0));
                return data;
            });
        }

        navigator.credentials.get({publicKey})
                 .then((data) =>
                 {
                     const publicKeyCredential = {
                         id:       data.id,
                         type:     data.type,
                         rawId:    arrayToBase64String(new Uint8Array(data.rawId)),
                         response: {
                             authenticatorData: arrayToBase64String(new Uint8Array(data.response.authenticatorData)),
                             clientDataJSON:    arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
                             signature:         arrayToBase64String(new Uint8Array(data.response.signature)),
                             userHandle:        data.response.userHandle ? arrayToBase64String(
                                 new Uint8Array(data.response.userHandle),
                             ) : null,
                         },
                     };

                     // Send the response to your server
                     window.location = `${callbackUrl}&option=com_ajax&group=system&plugin=passwordless&`
                         + `format=raw&akaction=login&encoding=redirect&data=${
                             btoa(JSON.stringify(publicKeyCredential))}`;
                 })
                 .catch((error) =>
                 {
                     // Example: timeout, interaction refused...
                     reportErrorToUser(error);
                 });
    };

    /**
     * Ask the user to link an authenticator using the provided public key (created server-side).
     * Posts the credentials to the URL defined in post_url using AJAX.
     * That URL must re-render the management interface.
     * These contents will replace the element identified by the interface_selector CSS selector.
     *
     * @param   {String}  storeID            CSS ID for the element storing the configuration in its
     *                                        data properties
     * @param   {String}  interfaceSelector  CSS selector for the GUI container
     */
    // eslint-disable-next-line no-unused-vars
    Passwordless.createCredentials = (storeID, interfaceSelector) =>
    {
        // Make sure the browser supports Webauthn
        if (!("credentials" in navigator))
        {
            reportErrorToUser(Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_NO_BROWSER_SUPPORT"));

            return;
        }

        // Extract the configuration from the store
        const elStore = document.getElementById(storeID);

        if (!elStore)
        {
            return;
        }

        const publicKey = JSON.parse(atob(elStore.dataset.public_key));
        const postURL   = atob(elStore.dataset.postback_url);

        const arrayToBase64String = (a) => btoa(String.fromCharCode(...a));

        const base64url2base64 = (input) =>
        {
            let output = input
                .replace(/-/g, "+")
                .replace(/_/g, "/");
            const pad  = output.length % 4;
            if (pad)
            {
                if (pad === 1)
                {
                    throw new Error(
                        "InvalidLengthError: Input base64url string is the wrong length to determine padding");
                }
                output += new Array(5 - pad).join("=");
            }
            return output;
        };

        // Convert the public key information to a format usable by the browser's credentials manager
        publicKey.challenge = Uint8Array.from(
            window.atob(base64url2base64(publicKey.challenge)), (c) => c.charCodeAt(0),
        );

        publicKey.user.id = Uint8Array.from(window.atob(publicKey.user.id), (c) => c.charCodeAt(0));

        if (publicKey.excludeCredentials)
        {
            publicKey.excludeCredentials = publicKey.excludeCredentials.map((data) =>
            {
                data.id = Uint8Array.from(window.atob(base64url2base64(data.id)), (c) => c.charCodeAt(0));
                return data;
            });
        }

        // Ask the browser to prompt the user for their authenticator
        navigator.credentials.create({publicKey})
                 .then((data) =>
                 {
                     const publicKeyCredential = {
                         id:       data.id,
                         type:     data.type,
                         rawId:    arrayToBase64String(new Uint8Array(data.rawId)),
                         response: {
                             clientDataJSON:    arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
                             attestationObject: arrayToBase64String(new Uint8Array(data.response.attestationObject)),
                         },
                     };

                     // Send the response to your server
                     const postBackData = {
                         option:   "com_ajax",
                         group:    "system",
                         plugin:   "passwordless",
                         format:   "raw",
                         akaction: "create",
                         encoding: "raw",
                         data:     btoa(JSON.stringify(publicKeyCredential)),
                     };

                     Joomla.request({
                         url:     postURL,
                         method:  "POST",
                         data:    interpolateParameters(postBackData),
                         onSuccess(responseHTML)
                         {
                             const elements = document.querySelectorAll(interfaceSelector);

                             if (!elements)
                             {
                                 return;
                             }

                             const elContainer = elements[0];

                             elContainer.outerHTML = responseHTML;

                             Passwordless.initManagement();
                         },
                         onError: (xhr) =>
                                  {
                                      reportErrorToUser(`${xhr.status} ${xhr.statusText}`);
                                  },
                     });
                 })
                 .catch((error) =>
                 {
                     // An error occurred: timeout, request to provide the authenticator refused, hardware /
                     // software error...
                     reportErrorToUser(error);
                 });
    };

    /**
     * Edit label button
     *
     * @param   {Element} that      The button being clicked
     * @param   {String}  storeID  CSS ID for the element storing the configuration in its data
     *                              properties
     */
    // eslint-disable-next-line no-unused-vars
    Passwordless.editLabel = (that, storeID) =>
    {
        // Extract the configuration from the store
        const elStore = document.getElementById(storeID);

        if (!elStore)
        {
            return false;
        }

        const postURL = atob(elStore.dataset.postback_url);

        // Find the UI elements
        const elTR         = that.parentElement.parentElement;
        const credentialId = elTR.dataset.credential_id;
        const elTDs        = elTR.querySelectorAll("td");
        const elLabelTD    = elTDs[0];
        const elButtonsTD  = elTDs[1];
        const elButtons    = elButtonsTD.querySelectorAll("button");
        const elEdit       = elButtons[0];
        const elDelete     = elButtons[1];

        // Show the editor
        const oldLabel = elLabelTD.innerText;

        const elInput        = document.createElement("input");
        elInput.type         = "text";
        elInput.name         = "label";
        elInput.defaultValue = oldLabel;

        const elSave     = document.createElement("button");
        elSave.className = "btn btn-success btn-sm";
        elSave.innerText = Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_SAVE_LABEL");
        elSave.addEventListener("click", () =>
        {
            const elNewLabel = elInput.value;

            if (elNewLabel !== "")
            {
                const postBackData = {
                    option:        "com_ajax",
                    group:         "system",
                    plugin:        "passwordless",
                    format:        "json",
                    encoding:      "json",
                    akaction:      "savelabel",
                    credential_id: credentialId,
                    new_label:     elNewLabel,
                };

                Joomla.request({
                    url:     postURL,
                    method:  "POST",
                    data:    interpolateParameters(postBackData),
                    onSuccess(rawResponse)
                    {
                        let result = false;

                        try
                        {
                            result = JSON.parse(rawResponse);
                        }
                        catch (exception)
                        {
                            result = (rawResponse === "true");
                        }

                        if (result !== true)
                        {
                            reportErrorToUser(
                                Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_LABEL_NOT_SAVED"),
                            );
                        }
                    },
                    onError: (xhr) =>
                             {
                                 reportErrorToUser(
                                     `${Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_LABEL_NOT_SAVED")
                                     } -- ${xhr.status} ${xhr.statusText}`,
                                 );
                             },
                });
            }

            elLabelTD.innerText = elNewLabel;
            elEdit.disabled     = false;
            elDelete.disabled   = false;

            return false;
        }, false);

        const elCancel     = document.createElement("button");
        elCancel.className = "btn btn-danger btn-sm";
        elCancel.innerText = Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_CANCEL_LABEL");
        elCancel.addEventListener("click", () =>
        {
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
    };

    /**
     * Delete button
     *
     * @param   {Element} that      The button being clicked
     * @param   {String}  storeID  CSS ID for the element storing the configuration in its data
     *                              properties
     */
    // eslint-disable-next-line no-unused-vars
    Passwordless.delete = (that, storeID) =>
    {
        // Extract the configuration from the store
        const elStore = document.getElementById(storeID);

        if (!elStore)
        {
            return false;
        }

        const postURL = atob(elStore.dataset.postback_url);

        // Find the UI elements
        const elTR         = that.parentElement.parentElement;
        const credentialId = elTR.dataset.credential_id;
        const elTDs        = elTR.querySelectorAll("td");
        const elButtonsTD  = elTDs[1];
        const elButtons    = elButtonsTD.querySelectorAll("button");
        const elEdit       = elButtons[0];
        const elDelete     = elButtons[1];

        elEdit.disabled   = true;
        elDelete.disabled = true;

        // Delete the record
        const postBackData = {
            option:        "com_ajax",
            group:         "system",
            plugin:        "passwordless",
            format:        "json",
            encoding:      "json",
            akaction:      "delete",
            credential_id: credentialId,
        };

        Joomla.request({
            url:     postURL,
            method:  "POST",
            data:    interpolateParameters(postBackData),
            onSuccess(rawResponse)
            {
                let result = false;

                try
                {
                    result = JSON.parse(rawResponse);
                }
                catch (e)
                {
                    result = (rawResponse === "true");
                }

                if (result !== true)
                {
                    reportErrorToUser(
                        Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_NOT_DELETED"),
                    );

                    return;
                }

                elTR.parentElement.removeChild(elTR);
            },
            onError: (xhr) =>
                     {
                         elEdit.disabled   = false;
                         elDelete.disabled = false;
                         reportErrorToUser(
                             `${Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_NOT_DELETED")
                             } -- ${xhr.status} ${xhr.statusText}`,
                         );
                     },
        });

        return false;
    };

    /**
     * Add New Authenticator button click handler
     *
     * @param   {MouseEvent} event  The mouse click event
     *
     * @returns {boolean} Returns false to prevent the default browser button behavior
     */
    Passwordless.addOnClick = (event) =>
    {
        event.preventDefault();

        Passwordless.createCredentials(
            event.currentTarget.getAttribute("data-random-id"), "#plg_system_passwordless-management-interface");

        return false;
    };

    /**
     * Edit Name button click handler
     *
     * @param   {MouseEvent} event  The mouse click event
     *
     * @returns {boolean} Returns false to prevent the default browser button behavior
     */
    Passwordless.editOnClick = (event) =>
    {
        event.preventDefault();

        Passwordless.editLabel(
            event.currentTarget, event.currentTarget.getAttribute("data-random-id"));

        return false;
    };

    /**
     * Remove button click handler
     *
     * @param   {MouseEvent} event  The mouse click event
     *
     * @returns {boolean} Returns false to prevent the default browser button behavior
     */
    Passwordless.deleteOnClick = (event) =>
    {
        event.preventDefault();

        Passwordless.delete(event.currentTarget, event.currentTarget.getAttribute("data-random-id"));

        return false;
    };

    /**
     * Moves the passwordless login button next to the existing Login button in the login module, if possible. This is
     * not a guaranteed success! We will *try* to find a button that looks like the login action button. If the
     * developer of the module or the site integrator doing template overrides didn't bother including some useful
     * information to help us identify it we're probably going to fail hard.
     *
     * @param   {Element}  elPasswordlessLoginButton  The login button to move.
     * @param   {Array}    possibleSelectors          The CSS selectors to use for moving the button.
     */
    Passwordless.moveButton = (elPasswordlessLoginButton, possibleSelectors) =>
    {
        if ((elPasswordlessLoginButton === null) || (elPasswordlessLoginButton === undefined))
        {
            return;
        }

        var elLoginBtn = null;

        for (var i = 0; i < possibleSelectors.length; i++)
        {
            var selector = possibleSelectors[i];

            elLoginBtn = lookForField(elPasswordlessLoginButton, selector);

            if (elLoginBtn !== null)
            {
                break;
            }
        }

        if (elLoginBtn === null)
        {
            return;
        }

        elLoginBtn.parentElement.appendChild(elPasswordlessLoginButton);
    }

    /**
     * Initialize the passwordless login, going through the server to get the registered certificates
     * for the user.
     *
     * @param   {Element}  that         The login button which was clicked
     * @param   {string}   callbackUrl  The URL we will use to post back to the server. Must include
     *   the anti-CSRF token.
     *
     * @returns {boolean}  Always FALSE to prevent BUTTON elements from reloading the page.
     */
    // eslint-disable-next-line no-unused-vars
    Passwordless.login = (that, callbackUrl) =>
    {
        // Get the username
        const elUsername = lookForField(that, "input[name=username]");
        const elReturn   = lookForField(that, "input[name=return]");

        if (elUsername === null)
        {
            reportErrorToUser(Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_CANNOT_FIND_USERNAME"));

            return false;
        }

        const username  = elUsername.value;
        const returnUrl = elReturn ? elReturn.value : null;

        // No username? We cannot proceed. We need a username to find the acceptable public keys :(
        if (username === "")
        {
            reportErrorToUser(Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_EMPTY_USERNAME"));

            return false;
        }

        // Get the Public Key Credential Request Options (challenge and acceptable public keys)
        const postBackData = {
            option:      "com_ajax",
            group:       "system",
            plugin:      "passwordless",
            format:      "raw",
            akaction:    "challenge",
            encoding:    "raw",
            "username":  username,
            "returnUrl": returnUrl
        };

        Joomla.request({
            url:     callbackUrl,
            method:  "POST",
            data:    interpolateParameters(postBackData),
            onSuccess(rawResponse)
            {
                let jsonData = {};

                try
                {
                    jsonData = JSON.parse(rawResponse);
                }
                catch (e)
                {
                    /**
                     * In case of JSON decoding failure fall through; the error will be handled in the login
                     * challenge handler called below.
                     */
                }

                handleLoginChallenge(jsonData, callbackUrl);
            },
            onError: (xhr) =>
                     {
                         reportErrorToUser(`${xhr.status} ${xhr.statusText}`);
                     },
        });

        return false;
    };

    /**
     * Initialization on page load.
     */
    Passwordless.initManagement = () =>
    {
        const addButton = document.getElementById("plg_system_passwordless-manage-add");

        if (addButton)
        {
            addButton.addEventListener("click", Passwordless.addOnClick);
        }

        const editLabelButtons = [].slice.call(document.querySelectorAll(".plg_system_passwordless-manage-edit"));
        if (editLabelButtons.length)
        {
            editLabelButtons.forEach((button) =>
            {
                button.addEventListener("click", Passwordless.editOnClick);
            });
        }

        const deleteButtons = [].slice.call(document.querySelectorAll(".plg_system_passwordless-manage-delete"));
        if (deleteButtons.length)
        {
            deleteButtons.forEach((button) =>
            {
                button.addEventListener("click", Passwordless.deleteOnClick);
            });
        }
    };

    Passwordless.initLogin = () =>
    {
        const loginButtons = [].slice.call(document.querySelectorAll(".plg_system_passwordless_login_button"));
        if (loginButtons.length)
        {
            loginButtons.forEach((button) =>
            {
                button.addEventListener("click", (e) =>
                {
                    e.preventDefault();

                    const currentTarget = e.currentTarget;

                    Passwordless.login(
                        currentTarget,
                        currentTarget.getAttribute("data-passwordless-url")
                    );
                });
            });
        }
    }

    // Initialization. Runs on DOM content loaded since this script is always loaded deferred.
    Passwordless.initManagement();
    Passwordless.initLogin();

})(Joomla, window.akeeba.Passwordless, document, window);
