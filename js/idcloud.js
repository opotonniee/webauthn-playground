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
      /**
       * Returns the base64-url encoded value of a bytes array or an ArrayBuffer
       * @param {*} bytes array or an ArrayBuffer to encode
       * @returns base64-url encoded value
       */
      bytesToBase64url: function (bytes) {
        const arrayBuf = ArrayBuffer.isView(bytes) ? bytes : new Uint8Array(bytes);
        const binString = Array.from(arrayBuf, (x) =>
           String.fromCodePoint(x)).join("");
        return btoa(binString).replaceAll("+", "-").replaceAll("/", "_")
          .replaceAll("=", "");
      },

      /**
       * Returns the ArrayBuffer resulting from the decoding of a base64-url encoded value
       * @param {*} base64-url encoded value
       * @returns decoded ArrayBuffer
       */
      base64urlToBytes: function (base64) {
        const padding = "====".substring(base64.length % 4);
        const binString = atob(base64.replaceAll("-", "+")
          .replaceAll("_", "/") + (padding.length < 4 ? padding : ""));
        return Uint8Array.from(binString, (m) => m.codePointAt(0));
      },

      /**
       * Returns true if a value is null or undefined
       * @param {*} a value
       * @returns true is null or undefined
       */
      isNotSet: function (value) {
        return value === null ||
        value === undefined;
      },

      /**
       * Returns true if a value is a Javascript basic type: string, boolean, number, bigint, null, or undefined
       * @param {*} a value
       * @returns true if the value is a Javascript basic type
       */
      isBasicValue: function(value) {
        return (typeof (value) === "string" ||
          typeof (value) === "boolean" ||
          typeof (value) === "number" ||
          typeof (value) === "bigint" ||
          this.isNotSet(value));
      },

      /**
       * Returns a modified version of a Javascript value where:
       *   - if a field name is listed in the `options.b64` string array, it is assumed to be a byte array or ArrayBuffer, and replaced by its base64-url encoded value.
       *   - if a field name is listed in the `options.toSkip` string array, it is skipped and omitted in the returned value.
       *   - if a field name is listed in the `options.any` string array, its children fields names are ignored and treated as a wildcard when evaluating `toSkip` or `b64` values.
       *
       * @param {*} val
       * @param {object} [options]
       * @param {string} [scopedName] don't set this value
       * @returns {*}
       */
      fromB64Json: function(val, options, scopedName) {
          const isIn = (arr, name) =>
            options && options[arr] && options[arr].includes(name);
          let res;
          if (isIn("toSkip", scopedName)) {
            // skip
          } else if (isIn("b64", scopedName)) {
            res = this.base64urlToBytes(val);
          } else if (this.isBasicValue(val)) {
            res = val;
          } else if (Array.isArray(val)) {
            res = [];
            for (const item of val) {
              const childScopedName = (scopedName || "") + "[]";
              const childValue = this.fromB64Json(item, options, childScopedName);
              res.push(childValue);
            }
          } else if (typeof (val) === "object") {
            res = {};
            for (const name in val) {
              let childScopedName = name;
              if (scopedName) {
                if (isIn("any", (scopedName.substring(0, scopedName.lastIndexOf('.'))))) {
                  childScopedName = scopedName + ".*";
                } else {
                  childScopedName = scopedName + "." + name;
                }
              }
              const tmp = this.fromB64Json(
                val[name], options, childScopedName);
              if (!this.isNotSet(tmp)) {
                res[name] = tmp;
              }
            }
          }
          return res;
      },

      /**
       * Returns a modified version of a Javascript value where
       *   - all byte arrays or ArrayBuffers are converted to their base64-url encoded value
       *   - fields listed in the `options.toSkip` string array are skipped and omitted in the returned value.
       *
       * @param {*} val
       * @param {object} options
       * @returns {*}
       */
      toB64Json: function(val, options) {
        const isIn = (arr, name) =>
          options && options[arr] && options[arr].includes(name);
        let res;
        if (this.isBasicValue(val)) {
          res = val;
        } else if (ArrayBuffer.isView(val) || val instanceof ArrayBuffer) {
          res = this.bytesToBase64url(val);
        } else if (Array.isArray(val)) {
          res = [];
          for (const item of val) {
            res.push(this.toB64Json(item, options));
          }
        } else if (typeof (val) === "object") {
          res = {};
          for (const name in val) {
            if (!isIn("toSkip", name)) {
              const tmp = this.toB64Json(val[name], options);
              if (!this.isNotSet(tmp)) {
                res[name] = tmp;
              }
            }
          }
        }
        return res;
      }

    };
  }


  static get API_V1() { return "v1" }
  static get API_V2() { return "v2" }

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

  /**
   * Constructor
   * @param {*} [options] may contain any of the following optional fields:
   *  - version: Version of the IdCloud API. Should be the latest (IdCloud.API_V2)
   *  - isUserIdTextual (boolean): should always be false: IdCloud provides a base64-encoded byte array
   *  - fido.usePlatformFIDO (boolean): true if should use credentials provided by the platform
   *  - fido.useRoamingFIDO (boolean): true if should use credentials provided by disconnectable devices (typically security keys)
   *  - fido.hints: an array of strings indicating where the credential is expected to be stored
   */
  constructor(options) {
    Object.assign(this.#options, IdCloud.#DEFAULT_OPTIONS);
    options ? Object.assign(this.#options, options) : false;
    IdCloud.#debug("[IdCloud]", JSON.stringify(this.#options));
    this.isFido2Available().then(yes => {
      if (!yes) {
        console.warn("!! WebAuthn is not available");
        const webAuthnElements = document.getElementsByClassName("idcloud-webauthn");
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
      const fidoSupported = (typeof window.PublicKeyCredential === "function");
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

  #setHints(requestOptions) {
    if (requestOptions.hints == undefined && this.#options.fido.hints != undefined) {
      if (Array.isArray(this.#options.fido.hints)) {
        requestOptions.hints = this.#options.fido.hints;
      } else if (typeof this.#options.fido.hints === "string") {
        requestOptions.hints = [this.#options.fido.hints];
      } else {
        console.error("Invalid 'hints' value (should be a string or an array of strings)");
      }
    }
  }

  #setCredProps(requestOptions) {
    requestOptions.extensions = requestOptions.extensions || {};
    requestOptions.extensions.credProps = true;
  }

  #getCredAaguid(credential) {

    /**
    * Lightweight CBOR decoder that handles the types needed for WebAuthn.
    *
    * @param {ArrayBuffer} cborBuffer The ArrayBuffer containing CBOR data.
    * @returns {object} The decoded JavaScript object.
    */
    const cborDecode = (cborBuffer) => {
      const dataView = new DataView(cborBuffer);
      let offset = 0;

      const read = () => {
        if (offset >= dataView.byteLength) throw new Error("CBOR decode: Unexpected end of buffer");
        const initialByte = dataView.getUint8(offset++);
        const majorType = initialByte >> 5;
        const additionalInfo = initialByte & 0x1f;

        const getLength = (info) => {
          if (info < 24) return info;
          switch (info) {
            case 24: return dataView.getUint8(offset++);
            case 25: offset += 2; return dataView.getUint16(offset - 2, false);
            case 26: offset += 4; return dataView.getUint32(offset - 4, false);
            case 27: offset += 8; return dataView.getBigUint64(offset - 8, false);
            default: throw new Error("CBOR decode: Unsupported length encoding");
          }
        };

        switch (majorType) {
          case 0: // Unsigned Integer
            return getLength(additionalInfo);

          case 1: // Negative Integer
            const val = getLength(additionalInfo);
            return typeof val === 'bigint' ? -1n - val : -1 - val;

          case 2: { // Byte string
            const len = getLength(additionalInfo);
            const bytes = new Uint8Array(dataView.buffer, offset, Number(len));
            offset += Number(len);
            return bytes;
          }
          case 3: { // Text string
            const len = getLength(additionalInfo);
            const bytes = new Uint8Array(dataView.buffer, offset, Number(len));
            offset += Number(len);
            return new TextDecoder("utf-8").decode(bytes);
          }
          case 5: { // Map
            const map = {};
            const len = getLength(additionalInfo);
            for (let i = 0; i < len; i++) map[read()] = read();
            return map;
          }
          default: throw new Error(`CBOR decode: Unsupported major type ${majorType}`);
        }
      };

      return read();
    };

    try {
      const decodedAttestation = cborDecode(credential.response.attestationObject);
      const authData = decodedAttestation.authData;
      if (!authData || !(authData[32] & (1 << 6))) {
        return null;
      }

      const aaguid = authData.slice(37, 37 + 16);
      const aaguidHex = Array.from(aaguid)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
      // Format as a standard GUID string.
      return `${aaguidHex.slice(0, 8)}-${aaguidHex.slice(8, 12)}-${aaguidHex.slice(12, 16)}-${aaguidHex.slice(16, 20)}-${aaguidHex.slice(20, 32)}`;

    } catch (error) {
      console.error("Failed to extract AAGUID:", error);
      return null;
    }
  }

  async #getCredName(credential, options) {

    // Compute a default name from user agent
    const defName = navigator.userAgent.replaceAll(/[0-9;:./()]/ig, "").split(' ').slice(1, 4).join(" ");
    let credName;

    // if callback defined, ask app
    if (options?.getCredName) {
      credName = options.getCredName(defName, this.#getCredAaguid(credential));
    } else if (options?.asyncGetCredName) {
      try {
        credName = await options.asyncGetCredName(defName, this.#getCredAaguid(credential));
      } catch (error) {
        console.error(error);
      }
    }

    return credName || defName;
  }

  static get #FROM_OPTIONS() {
    return {
      toSkip: [
        "status",
        "errorMessage",
        "thalesgroup_chl_tkn_ext_v1",
        "thalesgroup_ext_v1",
        "thalesgroup_txn_ext_v1"
      ],
      any: [
        "extensions.prf.evalByCredential"
      ],
      b64: [
        "challenge",
        "user.id",
        "excludeCredentials[].id",
        "allowCredentials[].id",
        "extensions.prf.eval.first",
        "extensions.prf.eval.second",
        "extensions.prf.evalByCredential.*.first",
        "extensions.prf.evalByCredential.*.second",
        "extensions.largeBlob.write",
        "response.authenticatorData",
        "response.clientDataJSON",
        "response.signature",
        "response.userHandle"
      ]
    };
  }

  static get #TO_OPTIONS() {
    return {
      toSkip: []
    };
  }

  /**
    * Run a WebAuthn registration (using `credentials.create()`)
   *
   * @param {*} pubKeyOptions the public key options (`publicKey` field) for the credential request
   * @param {*} [options] an object which can optionally contain:
   *   - `getCredName(defaultName)`: a callback for the application to provide the friendly name to assign to the created credential. `defaultName` is a proposed name generated by this library based on the browser "User-Agent" value.
   * @returns
   */
  async enroll(pubKeyOptions, options) {

    this.#setHints(pubKeyOptions);
    this.#setCredProps(pubKeyOptions);
    const createOptions = {
      publicKey: IdCloud.Utils.fromB64Json(
        pubKeyOptions, IdCloud.#FROM_OPTIONS)
    };

    IdCloud.#debug("[IdCloud] Create credential options (pk): " + JSON.stringify(IdCloud.Utils.toB64Json(createOptions)), createOptions);
    const credential = await navigator.credentials.create(createOptions);
    IdCloud.#debug("[IdCloud] Create credential ok: " + JSON.stringify(IdCloud.Utils.toB64Json(credential)), credential);

    credential.clientExtensionResults = credential.getClientExtensionResults() || {};
    const result = IdCloud.Utils.toB64Json(credential, IdCloud.#TO_OPTIONS);
    // getter for original authenticator response
    result.getCredential = () => credential;

    if (this.#options.version == IdCloud.API_V2) {
      if (typeof credential.response?.getTransports === "function") {
        result.response.transports = credential.response.getTransports();
      }
      if (typeof credential.response?.getPublicKeyAlgorithm === "function") {
        result.response.publicKeyAlgorithm = credential.response.getPublicKeyAlgorithm();
      }
    }
    // Add thales "friendly name" extension
    const credName = await this.#getCredName(credential, options);

    result.clientExtensionResults.thalesgroup_ext_v1 = {
      authenticatorDescription: {
        friendlyName: credName?.trim()
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

  async #processSPC(options) {

    const isSpcAvailable =
      PaymentRequest /*&&
      PaymentRequest.isSecurePaymentConfirmationAvailable &&
      await PaymentRequest.isSecurePaymentConfirmationAvailable()*/;

    if (!isSpcAvailable) {
      throw "Browser does not support SPC";
    }

    try {
      const request = new PaymentRequest([{
        supportedMethods: "secure-payment-confirmation",
        data: {
          // required fields
          challenge: options.challenge,
          rpId: options.extensions.payment.rpId,
          credentialIds: options.allowCredentials.map((c) => c.id),
          instrument: options.extensions.payment.instrument,
          // optional
          timeout: options.timeout,
          payeeName: options.extensions.payment?.payeeName,
          payeeOrigin: options.extensions.payment?.payeeOrigin,
          //extensions: TBD,
          locale: options.extensions.payment?.locale,
          showOptOut: options.extensions.payment?.showOptOut
        }}], {
          total: {
            label: "Total",
            amount: options.extensions.payment.total,
          }
        }
      );

      const response = await request.show();
      await response.complete('success');
      // spec says 'data', but chrome return 'details'
      const res = response?.details ? response.details : response.data;
      return res;
    } catch (err) {
      throw "SPC cannot be used";
    }
  }

  /**
   * Run a WebAuthn authentication (using `credentials.get()`)
   *
   * @param {*} pubKeyOptions the public key options (`publicKey` field) for the credential request
   * @param {*} [credentialReqOptions] optional parameters for the credential request, such as conditional mediation options
   * @returns
   */
  async authenticate(pubKeyOptions, credentialReqOptions) {

    const getOptions = {
      publicKey: IdCloud.Utils.fromB64Json(
        pubKeyOptions, IdCloud.#FROM_OPTIONS)
    };
    // shallow copy of credentialReqOptions to getOptions
    Object.assign(getOptions, credentialReqOptions);

    this.#setHints(getOptions.publicKey);

    IdCloud.#debug("[IdCloud] Get credential options: " + JSON.stringify(IdCloud.Utils.toB64Json(getOptions)), getOptions);
    let assertion;
    if (getOptions.publicKey.extensions?.payment?.isPayment) {
      assertion = await this.#processSPC(getOptions.publicKey);
    } else {
      assertion = await navigator.credentials.get(getOptions);
    }
    IdCloud.#debug("[IdCloud] Get credential ok: " + JSON.stringify(IdCloud.Utils.toB64Json(assertion)), assertion);

    assertion.clientExtensionResults = assertion.getClientExtensionResults() || {};
    const result = IdCloud.Utils.toB64Json(assertion, IdCloud.#TO_OPTIONS);
    // getter for original authenticator response
    result.getAssertion = () => assertion;

    // Copy token challenge extension from request if it was present
    if (pubKeyOptions?.extensions?.thalesgroup_chl_tkn_ext_v1) {
      result.clientExtensionResults.thalesgroup_chl_tkn_ext_v1 = pubKeyOptions.extensions.thalesgroup_chl_tkn_ext_v1;
    }

    return result;
  }

}
