/*
 * IdCloud.js
 *
 * (c) Thales DIS, 2021
 *
 * By default, it uses base64url from https://github.com/herrjemand/Base64URL-ArrayBuffer
 * It can be overridden by defining base64Decode and base64Encode methods in constructor options
 */

"use strict";
/* globals PublicKeyCredential, base64url */
class IdCloud {

  static get _DEFAULT_OPTIONS() {
    return {
      base64Decode: base64url.decode,
      base64Encode: base64url.encode,
      fido: {
        usePlatformFIDO: true,
        useRoamingFIDO: true
      }
    };
  }

  constructor(options) {
    this._options = {};
    Object.assign(this._options, IdCloud._DEFAULT_OPTIONS);
    options ? Object.assign(this._options, options) : false;
    //console.log(JSON.stringify(this._options));
    this.isFido2Available().then(yes => {
      if (!yes) {
        console.warn("!! WebAuthn not available");
        let webAuthnElts = document.getElementsByClassName("idcloud-webauthn");
        webAuthnElts.length && webAuthnElts.forEach((elt) => { elt.style.display = "none"; });
      } else {
        //console.debug("WebAuthn is available :)");
      }
    });
  }

  async isFido2Available() {
    let usePlatformFIDO = this._options.fido.usePlatformFIDO;
    let useRoamingFIDO = this._options.fido.useRoamingFIDO;
    return new Promise(function (resolve, reject) {
      let fidoSupported = (typeof window.PublicKeyCredential === "function");
      if (fidoSupported && !useRoamingFIDO && usePlatformFIDO) {
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(res => {
          resolve(res);
        });
      } else {
        resolve(useRoamingFIDO && fidoSupported);
      }
    });
  }

  async isAutoFillSupported() {
    return PublicKeyCredential.isConditionalMediationAvailable &&
     PublicKeyCredential.isConditionalMediationAvailable();
  }

  async enroll(credentialOptions, options) {
    credentialOptions.challenge = new Uint8Array(this._options.base64Decode(
      credentialOptions.challenge));
    credentialOptions.user.id = Uint8Array.from(
      credentialOptions.user.id, c => c.charCodeAt(0));
    credentialOptions.excludeCredentials.forEach(excludeCredential => {
      excludeCredential.id = this._options.base64Decode(excludeCredential.id);
    });
    const encode = this._options.base64Encode;

    let credential = await navigator.credentials.create({ publicKey: credentialOptions });
    //console.debug("make credential ok: ", JSON.stringify(credential));
    let credName = navigator.userAgent.replaceAll(/[0-9;:\.\/\(\)]/ig, "").split(' ').slice(1, 4).join(" ");
    if (options && options.getCredName) {
      let defName = credName;
      credName = options.getCredName(defName);
      credName = credName ? credName.trim() : null;
      if (!credName) {
        credName = defName;
      }
    }
    let rawId = new Uint8Array(credential.rawId);
    let attData = new Uint8Array(credential.response.attestationObject);
    let clientDataJSON = new Uint8Array(credential.response.clientDataJSON);
    let response = {
      attestationObject: encode(attData),
      clientDataJSON: encode(clientDataJSON)
    };

    if (credential.response.getAuthenticatorData) {
      response.getAuthenticatorData = credential.response.getAuthenticatorData;
    }
    if (credential.response.getTransports) {
      response.getTransports = () => credential.response.getTransports();
    }
    if (credential.response.getPublicKeyAlgorithm) {
      response.getPublicKeyAlgorithm = () => credential.response.getPublicKeyAlgorithm();
    }
    return {
      id: credential.id,
      rawId: encode(rawId),
      type: credential.type,
      response: response,
      // Add thales extension with friendly name
      clientExtensionResults: {
        thalesgroup_ext_v1: {
          authenticatorDescription: {
            friendlyName: credName
          }
        }
      }
    };
  }

  async authenticate(assertionOptions, credentialReqOptions) {
    assertionOptions.challenge = new Uint8Array(this._options.base64Decode(
      assertionOptions.challenge));
    if (assertionOptions.allowCredentials) {
      assertionOptions.allowCredentials.forEach(allowCredential => {
        allowCredential.id = this._options.base64Decode(allowCredential.id);
      });
    }
    const encode = this._options.base64Encode;

    let getOptions = credentialReqOptions ? credentialReqOptions : {};
    getOptions.publicKey = assertionOptions;
    let assertion = await navigator.credentials.get(getOptions);
    let rawId = new Uint8Array(assertion.rawId);
    let authData = new Uint8Array(assertion.response.authenticatorData);
    let clientDataJSON = new Uint8Array(assertion.response.clientDataJSON);
    let sig = new Uint8Array(assertion.response.signature);
    let userHandle = new Uint8Array(assertion.response.userHandle);
    return {
      id: assertion.id,
      rawId: encode(rawId),
      type: assertion.type,
      response: {
        authenticatorData: encode(authData),
        clientDataJSON: encode(clientDataJSON),
        signature: encode(sig),
        userHandle: encode(userHandle),
      }
    };
  }

}
