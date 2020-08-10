"use strict";function _toConsumableArray(arr){return _arrayWithoutHoles(arr)||_iterableToArray(arr)||_unsupportedIterableToArray(arr)||_nonIterableSpread();}function _nonIterableSpread(){throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.");}function _unsupportedIterableToArray(o,minLen){if(!o)return;if(typeof o==="string")return _arrayLikeToArray(o,minLen);var n=Object.prototype.toString.call(o).slice(8,-1);if(n==="Object"&&o.constructor)n=o.constructor.name;if(n==="Map"||n==="Set")return Array.from(o);if(n==="Arguments"||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n))return _arrayLikeToArray(o,minLen);}function _iterableToArray(iter){if(typeof Symbol!=="undefined"&&Symbol.iterator in Object(iter))return Array.from(iter);}function _arrayWithoutHoles(arr){if(Array.isArray(arr))return _arrayLikeToArray(arr);}function _arrayLikeToArray(arr,len){if(len==null||len>arr.length)len=arr.length;for(var i=0,arr2=new Array(len);i<len;i++){arr2[i]=arr[i];}return arr2;}function _typeof(obj){"@babel/helpers - typeof";if(typeof Symbol==="function"&&typeof Symbol.iterator==="symbol"){_typeof=function _typeof(obj){return typeof obj;};}else{_typeof=function _typeof(obj){return obj&&typeof Symbol==="function"&&obj.constructor===Symbol&&obj!==Symbol.prototype?"symbol":typeof obj;};}return _typeof(obj);}/*
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2020 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */window.Joomla=window.Joomla||{};window.akeeba=window.akeeba||{};window.akeeba.Passwordless=window.akeeba.Passwordless||{};(function(Joomla,Passwordless,document){"use strict";var interpolateParameters=function interpolateParameters(object){var prefix=arguments.length>1&&arguments[1]!==undefined?arguments[1]:"";var encodedString="";Object.keys(object).forEach(function(prop){if(_typeof(object[prop])!=="object"){if(encodedString.length>0){encodedString+="&";}if(prefix===""){encodedString+="".concat(encodeURIComponent(prop),"=").concat(encodeURIComponent(object[prop]));}else{encodedString+="".concat(encodeURIComponent(prefix),"[").concat(encodeURIComponent(prop),"]=").concat(encodeURIComponent(object[prop]));}return;}encodedString+="".concat(interpolateParameters(object[prop],prop));});return encodedString;};var findField=function findField(form,fieldSelector){var elInputs=form.querySelectorAll(fieldSelector);if(!elInputs.length){return null;}return elInputs[0];};var lookForField=function lookForField(innerElement,fieldSelector){var elElement=innerElement.parentElement;var elInput=null;while(true){if(!elElement){return null;}if(elElement.nodeName==="FORM"){elInput=lookForField(elElement,fieldSelector);if(elInput!==null){return elInput;}break;}var elForms=elElement.querySelectorAll("form");if(elForms.length){for(var i=0;i<elForms.length;i++){elInput=findField(elForms[i],fieldSelector);if(elInput!==null){return elInput;}}break;}elElement=elElement.parentElement;}return null;};var reportErrorToUser=function reportErrorToUser(message){Joomla.renderMessages({error:[message]});window.scrollTo({top:0,left:0,behavior:'smooth'});};var base64url2base64=function base64url2base64(input){var output=input.replace(/-/g,"+").replace(/_/g,"/");var pad=output.length%4;if(pad){if(pad===1){throw new Error("InvalidLengthError: Input base64url string is the wrong length to determine padding");}output+=new Array(5-pad).join("=");}return output;};var arrayToBase64String=function arrayToBase64String(a){return btoa(String.fromCharCode.apply(String,_toConsumableArray(a)));};var handleLoginChallenge=function handleLoginChallenge(publicKey,callbackUrl){if(!publicKey.challenge){reportErrorToUser(Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_INVALID_USERNAME"));return;}publicKey.challenge=Uint8Array.from(window.atob(base64url2base64(publicKey.challenge)),function(c){return c.charCodeAt(0);});if(publicKey.allowCredentials){publicKey.allowCredentials=publicKey.allowCredentials.map(function(data){data.id=Uint8Array.from(window.atob(base64url2base64(data.id)),function(c){return c.charCodeAt(0);});return data;});}console.log(publicKey);navigator.credentials.get({publicKey:publicKey}).then(function(data){var publicKeyCredential={id:data.id,type:data.type,rawId:arrayToBase64String(new Uint8Array(data.rawId)),response:{authenticatorData:arrayToBase64String(new Uint8Array(data.response.authenticatorData)),clientDataJSON:arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),signature:arrayToBase64String(new Uint8Array(data.response.signature)),userHandle:data.response.userHandle?arrayToBase64String(new Uint8Array(data.response.userHandle)):null}};window.location="".concat(callbackUrl,"&option=com_ajax&group=system&plugin=passwordless&")+"format=raw&akaction=login&encoding=redirect&data=".concat(btoa(JSON.stringify(publicKeyCredential)));})["catch"](function(error){reportErrorToUser(error);});};Passwordless.createCredentials=function(storeID,interfaceSelector){if(!("credentials"in navigator)){reportErrorToUser(Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_NO_BROWSER_SUPPORT"));return;}var elStore=document.getElementById(storeID);if(!elStore){return;}var publicKey=JSON.parse(atob(elStore.dataset.public_key));var postURL=atob(elStore.dataset.postback_url);publicKey.challenge=Uint8Array.from(window.atob(base64url2base64(publicKey.challenge)),function(c){return c.charCodeAt(0);});publicKey.user.id=Uint8Array.from(window.atob(publicKey.user.id),function(c){return c.charCodeAt(0);});if(publicKey.excludeCredentials){publicKey.excludeCredentials=publicKey.excludeCredentials.map(function(data){data.id=Uint8Array.from(window.atob(base64url2base64(data.id)),function(c){return c.charCodeAt(0);});return data;});}console.log(publicKey);navigator.credentials.create({publicKey:publicKey}).then(function(data){var publicKeyCredential={id:data.id,type:data.type,rawId:arrayToBase64String(new Uint8Array(data.rawId)),response:{clientDataJSON:arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),attestationObject:arrayToBase64String(new Uint8Array(data.response.attestationObject))}};var postBackData={option:"com_ajax",group:"system",plugin:"passwordless",format:"raw",akaction:"create",encoding:"raw",data:btoa(JSON.stringify(publicKeyCredential))};Joomla.request({url:postURL,method:"POST",data:interpolateParameters(postBackData),onSuccess:function onSuccess(responseHTML){var elements=document.querySelectorAll(interfaceSelector);if(!elements){return;}var elContainer=elements[0];elContainer.outerHTML=responseHTML;Passwordless.initManagement();},onError:function onError(xhr){reportErrorToUser("".concat(xhr.status," ").concat(xhr.statusText));}});})["catch"](function(error){reportErrorToUser(error);});};Passwordless.editLabel=function(that,storeID){var elStore=document.getElementById(storeID);if(!elStore){return false;}var postURL=atob(elStore.dataset.postback_url);var elTR=that.parentElement.parentElement;var credentialId=elTR.dataset.credential_id;var elTDs=elTR.querySelectorAll("td");var elLabelTD=elTDs[0];var elButtonsTD=elTDs[1];var elButtons=elButtonsTD.querySelectorAll("button");var elEdit=elButtons[0];var elDelete=elButtons[1];var oldLabel=elLabelTD.innerText;var elInput=document.createElement("input");elInput.type="text";elInput.name="label";elInput.defaultValue=oldLabel;var elSave=document.createElement("button");elSave.className="btn btn-success btn-sm";elSave.innerText=Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_SAVE_LABEL");elSave.addEventListener("click",function(){var elNewLabel=elInput.value;if(elNewLabel!==""){var postBackData={option:"com_ajax",group:"system",plugin:"passwordless",format:"json",encoding:"json",akaction:"savelabel",credential_id:credentialId,new_label:elNewLabel};Joomla.request({url:postURL,method:"POST",data:interpolateParameters(postBackData),onSuccess:function onSuccess(rawResponse){var result=false;try{result=JSON.parse(rawResponse);}catch(exception){result=rawResponse==="true";}if(result!==true){reportErrorToUser(Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_LABEL_NOT_SAVED"));}},onError:function onError(xhr){reportErrorToUser("".concat(Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_LABEL_NOT_SAVED")," -- ").concat(xhr.status," ").concat(xhr.statusText));}});}elLabelTD.innerText=elNewLabel;elEdit.disabled=false;elDelete.disabled=false;return false;},false);var elCancel=document.createElement("button");elCancel.className="btn btn-danger btn-sm";elCancel.innerText=Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_MANAGE_BTN_CANCEL_LABEL");elCancel.addEventListener("click",function(){elLabelTD.innerText=oldLabel;elEdit.disabled=false;elDelete.disabled=false;return false;},false);elLabelTD.innerHTML="";elLabelTD.appendChild(elInput);elLabelTD.appendChild(elSave);elLabelTD.appendChild(elCancel);elEdit.disabled=true;elDelete.disabled=true;return false;};Passwordless["delete"]=function(that,storeID){var elStore=document.getElementById(storeID);if(!elStore){return false;}var postURL=atob(elStore.dataset.postback_url);var elTR=that.parentElement.parentElement;var credentialId=elTR.dataset.credential_id;var elTDs=elTR.querySelectorAll("td");var elButtonsTD=elTDs[1];var elButtons=elButtonsTD.querySelectorAll("button");var elEdit=elButtons[0];var elDelete=elButtons[1];elEdit.disabled=true;elDelete.disabled=true;var postBackData={option:"com_ajax",group:"system",plugin:"passwordless",format:"json",encoding:"json",akaction:"delete",credential_id:credentialId};Joomla.request({url:postURL,method:"POST",data:interpolateParameters(postBackData),onSuccess:function onSuccess(rawResponse){var result=false;try{result=JSON.parse(rawResponse);}catch(e){result=rawResponse==="true";}if(result!==true){reportErrorToUser(Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_NOT_DELETED"));return;}elTR.parentElement.removeChild(elTR);},onError:function onError(xhr){elEdit.disabled=false;elDelete.disabled=false;reportErrorToUser("".concat(Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_NOT_DELETED")," -- ").concat(xhr.status," ").concat(xhr.statusText));}});return false;};Passwordless.addOnClick=function(event){event.preventDefault();Passwordless.createCredentials(event.currentTarget.getAttribute("data-random-id"),"#plg_system_passwordless-management-interface");return false;};Passwordless.editOnClick=function(event){event.preventDefault();Passwordless.editLabel(event.currentTarget,event.currentTarget.getAttribute("data-random-id"));return false;};Passwordless.deleteOnClick=function(event){event.preventDefault();Passwordless["delete"](event.currentTarget,event.currentTarget.getAttribute("data-random-id"));return false;};Passwordless.moveButton=function(elPasswordlessLoginButton,possibleSelectors){if(elPasswordlessLoginButton===null||elPasswordlessLoginButton===undefined){return;}var elLoginBtn=null;for(var i=0;i<possibleSelectors.length;i++){var selector=possibleSelectors[i];elLoginBtn=lookForField(elPasswordlessLoginButton,selector);if(elLoginBtn!==null){break;}}if(elLoginBtn===null){return;}elLoginBtn.parentElement.appendChild(elPasswordlessLoginButton);};Passwordless.login=function(that,callbackUrl){var elUsername=lookForField(that,"input[name=username]");var elReturn=lookForField(that,"input[name=return]");if(elUsername===null){reportErrorToUser(Joomla.JText._("PLG_SYSTEM_PASSWORDLESS_ERR_CANNOT_FIND_USERNAME"));return false;}var username=elUsername.value;var returnUrl=elReturn?elReturn.value:null;var postBackData={option:"com_ajax",group:"system",plugin:"passwordless",format:"raw",akaction:"challenge",encoding:"raw","username":username,"returnUrl":returnUrl};Joomla.request({url:callbackUrl,method:"POST",data:interpolateParameters(postBackData),onSuccess:function onSuccess(rawResponse){var jsonData={};try{jsonData=JSON.parse(rawResponse);}catch(e){}if(jsonData.error){reportErrorToUser(jsonData.error);return;}handleLoginChallenge(jsonData,callbackUrl);},onError:function onError(xhr){reportErrorToUser("".concat(xhr.status," ").concat(xhr.statusText));}});return false;};Passwordless.initManagement=function(){var addButton=document.getElementById("plg_system_passwordless-manage-add");if(addButton){addButton.addEventListener("click",Passwordless.addOnClick);}var editLabelButtons=[].slice.call(document.querySelectorAll(".plg_system_passwordless-manage-edit"));if(editLabelButtons.length){editLabelButtons.forEach(function(button){button.addEventListener("click",Passwordless.editOnClick);});}var deleteButtons=[].slice.call(document.querySelectorAll(".plg_system_passwordless-manage-delete"));if(deleteButtons.length){deleteButtons.forEach(function(button){button.addEventListener("click",Passwordless.deleteOnClick);});}};Passwordless.initLogin=function(){var loginButtons=[].slice.call(document.querySelectorAll(".plg_system_passwordless_login_button"));if(loginButtons.length){loginButtons.forEach(function(button){button.addEventListener("click",function(e){e.preventDefault();var currentTarget=e.currentTarget;Passwordless.login(currentTarget,currentTarget.getAttribute("data-passwordless-url"));});});}};Passwordless.initManagement();Passwordless.initLogin();})(Joomla,window.akeeba.Passwordless,document);
//# sourceMappingURL=passwordless.js.map