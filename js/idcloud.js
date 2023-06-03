/*
 * IdCloud.js
 *
 * (c) Thales DIS, 2021-2023
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
      isUserIdTextual: false, // should always be false: IdCloud provides a base64-encoded byte array
      fido: {
        usePlatformFIDO: true,
        useRoamingFIDO: true
      }
    };
  }

  static _DEBUG = true;
  static _debug(...args) {
    if (IdCloud._DEBUG) {
      console.debug(...args);
    }
  }

  constructor(options) {
    this._options = {};
    Object.assign(this._options, IdCloud._DEFAULT_OPTIONS);
    options ? Object.assign(this._options, options) : false;
    this.constructor._debug("[IdCloud]", JSON.stringify(this._options));
    this.isFido2Available().then(yes => {
      if (!yes) {
        console.warn("!! WebAuthn is not available");
        let webAuthnElts = document.getElementsByClassName("idcloud-webauthn");
        webAuthnElts.length && webAuthnElts.forEach((elt) => { elt.style.display = "none"; });
      } else {
        this.constructor._debug("[IdCloud] WebAuthn is available :)");
      }
    });
  }

  async isFido2Available() {
    const usePlatformFIDO = this._options.fido.usePlatformFIDO;
    const useRoamingFIDO = this._options.fido.useRoamingFIDO;
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
    return PublicKeyCredential.isConditionalMediationAvailable !== undefined &&
     PublicKeyCredential.isConditionalMediationAvailable();
  }

  _decodePRF(prf) {
    if (prf) {
      ["first", "second"].forEach(element => {
        if (prf[element]) {
          prf[element] = this._options.base64Decode(prf[element]);
        }
      });
    }
  }

  async enroll(credentialOptions, options) {
    const b64encode = this._options.base64Encode;
    const b64decode = this._options.base64Decode;

    credentialOptions.challenge = new Uint8Array(b64decode(
      credentialOptions.challenge));
    credentialOptions.user.id = this._options.isUserIdTextual ?
      new TextEncoder().encode(credentialOptions.user.id)
      : b64decode(credentialOptions.user.id);
    credentialOptions.excludeCredentials.forEach(excludeCredential => {
      excludeCredential.id = b64decode(excludeCredential.id);
    });
    this._decodePRF(credentialOptions?.extensions?.prf?.eval);

    const credential = await navigator.credentials.create({ publicKey: credentialOptions });
    this.constructor._debug("[IdCloud] Create credential ok:", credential);
    let credName = navigator.userAgent.replaceAll(/[0-9;:\.\/\(\)]/ig, "").split(' ').slice(1, 4).join(" ");
    if (options && options.getCredName) {
      const defName = credName;
      credName = options.getCredName(defName);
      credName = credName ? credName.trim() : null;
      if (!credName) {
        credName = defName;
      }
    }
    const rawId = b64encode(new Uint8Array(credential.rawId));
    const response = {
      attestationObject: b64encode(new Uint8Array(credential.response.attestationObject)),
      clientDataJSON: b64encode(new Uint8Array(credential.response.clientDataJSON))
    };

    if (typeof credential.response.getAuthenticatorData === "function") {
      response.getAuthenticatorData = credential.response.getAuthenticatorData;
    }
    if (typeof credential.response.getTransports === "function") {
      // transports are returned in the JSON object so that it can be stored on server
      response.transports = credential.response.getTransports();
    }
    if (typeof credential.response.getPublicKeyAlgorithm === "function") {
      response.getPublicKeyAlgorithm = () => credential.response.getPublicKeyAlgorithm();
    }
    let clientExtensionResults = credential.getClientExtensionResults();
    if (!clientExtensionResults) clientExtensionResults = {};
    clientExtensionResults.thalesgroup_ext_v1 = {
      authenticatorDescription: {
        friendlyName: credName
      }
    };
    return {
      id: credential.id,
      rawId: rawId,
      type: credential.type,
      response: response,
      // Add thales extension with friendly name
      clientExtensionResults: clientExtensionResults
    };
  }

  async authenticate(assertionOptions, credentialReqOptions) {
    const b64encode = this._options.base64Encode;
    const b64decode = this._options.base64Decode;

    assertionOptions.challenge = new Uint8Array(b64decode(
      assertionOptions.challenge));
    if (assertionOptions.allowCredentials) {
      assertionOptions.allowCredentials.forEach(allowCredential => {
        allowCredential.id = b64decode(allowCredential.id);
      });
    }
    this._decodePRF(assertionOptions?.extensions?.prf?.eval);

    const getOptions = credentialReqOptions ? credentialReqOptions : {};
    getOptions.publicKey = assertionOptions;
    const assertion = await navigator.credentials.get(getOptions);
    this.constructor._debug("[IdCloud] Get credential ok:", assertion);

    const rawId = b64encode(new Uint8Array(assertion.rawId));
    const authData = b64encode(new Uint8Array(assertion.response.authenticatorData));
    const clientDataJSON = b64encode(new Uint8Array(assertion.response.clientDataJSON));
    const signature = b64encode(new Uint8Array(assertion.response.signature));
    const userHandle = this._options.isUserIdTextual ?
      new TextDecoder().decode(assertion.response.userHandle)
      : b64encode(new Uint8Array(assertion.response.userHandle));

    const clientExtensionResults = assertion.getClientExtensionResults();
    if (clientExtensionResults?.prf?.results) {
      ["first", "second"].forEach(element => {
        let value = clientExtensionResults.prf.results[element];
        if (value) {
          value = b64encode(new Uint8Array(value));
        }
      });
    }

    const result = {
      id: assertion.id,
      rawId: rawId,
      type: assertion.type,
      response: {
        authenticatorData: authData,
        clientDataJSON: clientDataJSON,
        signature: signature,
        userHandle: userHandle,
      }
    };

    if (JSON.stringify(clientExtensionResults) !== '{}') {
      result.clientExtensionResults = clientExtensionResults;
    }

    return result;
  }

}
