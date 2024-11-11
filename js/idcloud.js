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

  #toJsonObject(obj) {
    const TO_SKIP = [
      "toJSON"
    ];
    const res = {};
    for (const name in obj) {
      const val = obj[name];
      if (TO_SKIP.includes(name)) {
        // skip
      } else if (typeof (val) === "string" ||
        typeof (val) === "boolean" ||
        typeof (val) === "number") {
        res[name] = val;
      } else if (val instanceof ArrayBuffer) {
        res[name] = IdCloud.Utils.bytesToBase64url(val);
      } else if (typeof (val) === "function") {
        res[name] = () => obj[name]();
      } else if (typeof (val) === "object") {
        res[name] = this.#toJsonObject(val);
      }
    }
    return res;
  }

  #fromJsonObject(prefix, obj) {
    const
      TO_SKIP = [
        "status",
        "errorMessage",
        "thalesgroup_chl_tkn_ext_v1",
        "thalesgroup_ext_v1",
        "thalesgroup_txn_ext_v1"
      ],
      ANY = [
        "extensions.prf.evalByCredential"
      ],
      B64 = [
        "challenge",
        "user.id",
        "excludeCredentials[].id",
        "allowCredentials[].id",
        "extensions.prf.eval.first",
        "extensions.prf.eval.second",
        "extensions.prf.evalByCredential.*.first",
        "extensions.prf.evalByCredential.*.second",
        "extensions.prf.result.first",
        "extensions.prf.result.second",
        "extensions.largeBlob.write",
        "response.authenticatorData",
        "response.clientDataJSON",
        "response.signature",
        "response.userHandle"
      ];

    const res = {};
    for (const name in obj) {
      const val = obj[name];
      let fullName = prefix ? prefix + "." + name : name;
      if (TO_SKIP.includes(fullName)) {
        // skip
      } else if (B64.includes(fullName)) {
          res[name] = IdCloud.Utils.base64urlToBytes(val);
      } else if (typeof (val) === "string" ||
        typeof (val) === "boolean" ||
        typeof (val) === "number") {
        res[name] = val;
      } else if (Array.isArray(val)) {
        res[name] = [];
        for (let item of val) {
          res[name].push(this.#fromJsonObject(fullName + "[]", item));
        }
      } else if (typeof (val) === "function") {
        res[name] = () => obj[name]();
      } else if (typeof (val) === "object") {
        if (ANY.includes(fullName.substring(0, fullName.lastIndexOf('.')))) {
          fullName = prefix + ".*"
        }
        res[name] = this.#fromJsonObject(fullName, val);
      }
    }
    return res;
  }

  async enroll(pubKeyOptions, options) {

    this.#setHints(pubKeyOptions);
    this.#setCredProps(pubKeyOptions);
    const createOptions = {
      publicKey: this.#fromJsonObject(null, pubKeyOptions)
    };

    IdCloud.#debug("[IdCloud] Create credential options (pk):", createOptions);
    const credential = await navigator.credentials.create(createOptions);
    IdCloud.#debug("[IdCloud] Create credential ok:", credential);

    const result = this.#toJsonObject(credential);

    if (this.#options.version == IdCloud.API_V2) {
      result.response.transports =
        this.#getOptionalFunctionValue(result.response.getTransports);
      result.response.publicKeyAlgorithm =
        this.#getOptionalFunctionValue(result.response.getPublicKeyAlgorithm);
    }
    result.clientExtensionResults = result.getClientExtensionResults() || {};
    // Add thales "friendly name" extension
    let credName = this.#getCredName(credential, options);
    result.clientExtensionResults.thalesgroup_ext_v1 = {
      authenticatorDescription: {
        friendlyName: credName
      }
    };
    // Add thales "client type" extension
    result.clientExtensionResults.thalesgroup_client_ext_v1 = {
      clientType: 1
    };
    // Copy token challenge extension from request if it was present
    if (pubKeyOptions?.extensions?.thalesgroup_chl_tkn_ext_v1) {
      result.clientExtensionResults.thalesgroup_chl_tkn_ext_v1 = pubKeyOptions.extensions.thalesgroup_chl_tkn_ext_v1;
    }

    return result;
  }

  async authenticate(pubKeyOptions, credentialReqOptions) {

    const getOptions = {
      publicKey: this.#fromJsonObject(null, pubKeyOptions)
    };
    // shallow copy of credentialReqOptions to getOptions
    Object.assign(getOptions, credentialReqOptions);

    this.#setHints(getOptions.publicKey);

    IdCloud.#debug("[IdCloud] Get credential options:", getOptions);
    const assertion = await navigator.credentials.get(getOptions);
    IdCloud.#debug("[IdCloud] Get credential ok:", assertion);

    const result = this.#toJsonObject(assertion);

    result.clientExtensionResults = assertion.getClientExtensionResults() || {};
    // Copy token challenge extension from request if it was present
    if (pubKeyOptions?.extensions?.thalesgroup_chl_tkn_ext_v1) {
      result.clientExtensionResults.thalesgroup_chl_tkn_ext_v1 = pubKeyOptions.extensions.thalesgroup_chl_tkn_ext_v1;
    }

    return result;
  }

}
