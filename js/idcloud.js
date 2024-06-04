/*
 * IdCloud.js
 *
 * (c) Thales DIS, 2021-2023
 *
 */

"use strict";
/* globals PublicKeyCredential */

// eslint-disable-next-line no-unused-vars
class IdCloud {

  static get Utils() {
    return {
      bytesToBase64url: function (bytes) {
        const arrayBuf = ArrayBuffer.isView(bytes) ? bytes : new Uint8Array(bytes);
        const binString = Array.from(arrayBuf, (x) => String.fromCodePoint(x)).join("");
        return btoa(binString).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
      },

      base64urlToBytes: function (base64) {
        const padding = "====".substring(base64.length % 4);
        const binString = atob(base64.replaceAll("-", "+").replaceAll("_", "/") + (padding.length < 4 ? padding : ""));
        return Uint8Array.from(binString, (m) => m.codePointAt(0));
      }
    };
  }


  static API_V1 = "v1";
  static API_V2 = "v2";

  static get #DEFAULT_OPTIONS() {
    return {
      isUserIdTextual: false, // should always be false: IdCloud provides a base64-encoded byte array
      fido: {
        usePlatformFIDO: true,
        useRoamingFIDO: true,
        hints: undefined
      },
      version: IdCloud.API_V2
    };
  }

  static #DEBUG = true;
  static #debug(...args) {
    if (IdCloud.#DEBUG) {
      console.debug(...args);
    }
  }

  #options = {};
  constructor(options) {
    Object.assign(this.#options, IdCloud.#DEFAULT_OPTIONS);
    options ? Object.assign(this.#options, options) : false;
    IdCloud.#debug("[IdCloud]", JSON.stringify(this.#options));
    this.isFido2Available().then(yes => {
      if (!yes) {
        console.warn("!! WebAuthn is not available");
        let webAuthnElements = document.getElementsByClassName("idcloud-webauthn");
        webAuthnElements.length && webAuthnElements.forEach((elt) => { elt.style.display = "none"; });
      } else {
        IdCloud.#debug("[IdCloud] WebAuthn is available :)");
      }
    });
  }

  async isFido2Available() {
    const usePlatformFIDO = this.#options.fido.usePlatformFIDO;
    const useRoamingFIDO = this.#options.fido.useRoamingFIDO;
    return new Promise(function (resolve) {
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

  #decodePRF(prf) {
    if (prf) {
      ["first", "second"].forEach(element => {
        if (prf[element]) {
          prf[element] = IdCloud.Utils.base64urlToBytes(prf[element]);
        }
      });
    }
  }

  #copyFunction(name, from, to) {
    if (typeof from[name] === "function") {
      to[name] = () => from[name]();
    }
  }
  #getOptionalFunctionValue(fn) {
    try {
      if (typeof fn === "function") {
        return fn();
      }
    } catch (err) {
      console.error(`Ignored error while accessing ${fn.name}: ${err}`);
    }
  }

  #setHints(requestOptions) {
    if (requestOptions.hints == undefined && this.#options.fido.hints != undefined) {
      if (Array.isArray(this.#options.fido.hints)) {
        requestOptions.hints = this.#options.fido.hints;
      } else if (typeof this.#options.fido.hints === "string") {
        requestOptions.hints = [ this.#options.fido.hints ];
      } else {
        console.error("Invalid 'hints' value (should be a string or an array of strings)")
      }
    }
  }

  #setCredProps(requestOptions) {
    requestOptions.extensions = requestOptions.extensions || {};
    requestOptions.extensions.credProps = true;
  }

  #getCredName(credential, options) {

    // default to authenticator's name if provided
    let credName = credential.getClientExtensionResults()?.credProps?.authenticatorDisplayName;
    // if not, compute a default name from user agent
    credName = credName ? credName : navigator.userAgent.replaceAll(/[0-9;:./()]/ig, "").split(' ').slice(1, 4).join(" ");

    // if callback defined, ask app
    if (options && options.getCredName) {
      const defName = credName;
      credName = options.getCredName(defName);
      credName = credName ? credName.trim() : null;
      if (!credName) {
        credName = defName;
      }
    }

    return credName;
  }

  #cleanupOptions(options) {
    let cleanOptions = {};
    // shallow copy of credentialReqOptions to getOptions
    Object.assign(cleanOptions, options);

    // delete FIDO2 server response fields if present
    delete cleanOptions.status;
    delete cleanOptions.errorMessage;

    return cleanOptions;
  }

  async enroll(credentialOptions, options) {
    const b64encode = IdCloud.Utils.bytesToBase64url;
    const b64decode = IdCloud.Utils.base64urlToBytes;

    credentialOptions = this.#cleanupOptions(credentialOptions);

    credentialOptions.challenge = b64decode(credentialOptions.challenge);
    credentialOptions.user.id = this.#options.isUserIdTextual ?
      new TextEncoder().encode(credentialOptions.user.id)
      : b64decode(credentialOptions.user.id);
    if (credentialOptions.excludeCredentials) {
      credentialOptions.excludeCredentials.forEach(excludeCredential => {
        excludeCredential.id = b64decode(excludeCredential.id);
      });
    }

    this.#setHints(credentialOptions);
    this.#setCredProps(credentialOptions);
    this.#decodePRF(credentialOptions?.extensions?.prf?.eval);

    IdCloud.#debug("[IdCloud] Create credential options (pk):", credentialOptions);
    const credential = await navigator.credentials.create({ publicKey: credentialOptions });
    IdCloud.#debug("[IdCloud] Create credential ok:", credential);

    let credName = this.#getCredName(credential, options);

    const rawId = b64encode(credential.rawId);
    const response = {
      attestationObject: b64encode(credential.response.attestationObject),
      clientDataJSON: b64encode(credential.response.clientDataJSON)
    };

    [
      "getAuthenticatorData",
      "getTransports",
      "getPublicKeyAlgorithm",
      "getPublicKey"
    ].forEach(fn => {
      this.#copyFunction(fn, credential.response, response);
    });
    if (this.#options.version == IdCloud.API_V2) {
      response.transports = this.#getOptionalFunctionValue(response.getTransports);
      response.publicKeyAlgorithm = this.#getOptionalFunctionValue(response.getPublicKeyAlgorithm);
    }
    let clientExtensionResults = credential.getClientExtensionResults();
    if (!clientExtensionResults) clientExtensionResults = {};
    // Add thales "friendly name" extension
    clientExtensionResults.thalesgroup_ext_v1 = {
      authenticatorDescription: {
        friendlyName: credName
      }
    };
    // Add thales "client type" extension
    clientExtensionResults.thalesgroup_client_ext_v1 = {
      clientType: 1
    };

    const result = {
      id: credential.id,
      rawId: rawId,
      type: credential.type,
      response: response,
      authenticatorAttachment: this.#options.version == IdCloud.API_V1 ? undefined : credential.authenticatorAttachment,
      clientExtensionResults: clientExtensionResults
    };
    [
      "isConditionalMediationAvailable"
    ].forEach(fn => {
      this.#copyFunction(fn, credential, result);
    });
    return result;
  }

  async authenticate(assertionOptions, credentialReqOptions) {
    const b64encode = IdCloud.Utils.bytesToBase64url;
    const b64decode = IdCloud.Utils.base64urlToBytes;

    assertionOptions = this.#cleanupOptions(assertionOptions);
    assertionOptions.challenge = b64decode(assertionOptions.challenge);
    if (assertionOptions.allowCredentials) {
      assertionOptions.allowCredentials.forEach(allowCredential => {
        allowCredential.id = b64decode(allowCredential.id);
      });
    }
    this.#decodePRF(assertionOptions?.extensions?.prf?.eval);

    const getOptions = {
      publicKey: assertionOptions
    };
    // shallow copy of credentialReqOptions to getOptions
    Object.assign(getOptions, credentialReqOptions);

    this.#setHints(getOptions.publicKey);

    IdCloud.#debug("[IdCloud] Get credential options:", getOptions);
    const assertion = await navigator.credentials.get(getOptions);
    IdCloud.#debug("[IdCloud] Get credential ok:", assertion);

    const rawId = b64encode(assertion.rawId);
    const authData = b64encode(assertion.response.authenticatorData);
    const clientDataJSON = b64encode(assertion.response.clientDataJSON);
    const signature = b64encode(assertion.response.signature);
    const userHandle = this.#options.isUserIdTextual ?
      new TextDecoder().decode(assertion.response.userHandle)
      : b64encode(assertion.response.userHandle);

    const clientExtensionResults = assertion.getClientExtensionResults();
    if (clientExtensionResults?.prf?.results) {
      for (let element of ["first", "second"]) {
        let value = clientExtensionResults.prf.results[element];
        if (value) {
          clientExtensionResults.prf.results[element] = b64encode(value);
        }
      }
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

    [
      "isConditionalMediationAvailable"
    ].forEach(fn => {
      this.#copyFunction(fn, assertion, result);
    });
    if (this.#options.version == IdCloud.API_V2) {
      result.authenticatorAttachment = assertion.authenticatorAttachment ? assertion.authenticatorAttachment : undefined;
    }

    if (JSON.stringify(clientExtensionResults) !== '{}') {
      result.clientExtensionResults = clientExtensionResults;
    }

    return result;
  }

}
