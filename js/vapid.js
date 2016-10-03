/* Javascript VAPID library.
 *
 * Requires: common.js
 *
 */

'use strict';

try {
    if (webCrypto === undefined) {
        webCrypto = window.crypto.subtle;
    }
} catch (e) {
    var webCrypto = window.crypto.subtle;
}

class VapidToken {
    constructor(aud, sub, exp, lang, mzcc) {
        /* Construct a base VAPID token.
         *
         * VAPID allows for self identification of a subscription update.
         *
         * :param sub: Subscription - email of the admin contact for this
         *      update.
         * :param exp: Expiration - UTC expiration of this update. Defaults
         *      to now + 24 hours
         */

        if (mzcc == undefined) {
            mzcc = new MozCommon();
        }
        this.mzcc = mzcc;
        this._claims={};
        this._claims['aud'] = aud || "";
        if (sub !== undefined) {
            this._claims['sub'] = sub;
        }
        if (exp == undefined) {
            // Set expry to be 24 hours from now.
            exp = (Date.now() * .001) + 86400
        }
        this._claims["exp"] = exp
        let enus = {
            info: {
                OK_VAPID_KEYS: "VAPID Keys defined.",
            },
            errs: {
                ERR_VAPID_KEY: "VAPID generate keys error: ",
                ERR_PUB_R_KEY: "Invalid Public Key record. Please use a valid RAW Formatted record.",
                ERR_PUB_D_KEY: "Invalid Public Key record. Please use a valid DER Formatted record.",
                ERR_NO_KEYS: "No keys defined. Please use generate_keys() or load a public key.",
                ERR_CLAIM_MIS: "Claim missing ",
                ERR_SIGN: "Sign error",
                ERR_VERIFY_SG: "Verify Error: Auth signature invalid: ",
                ERR_VERIFY_KE: "Verify Error: Key invalid: ",
                ERR_SIGNATURE: "Signature Invalid",
                ERR_VERIFY: "Verify error",
            }
        };
        this.lang = enus;

        this._private_key =  "";
        this._public_key = "";

    }

    generate_keys() {
       /* Generate the public and private keys
        */
       return webCrypto.generateKey(
          {name: "ECDSA", namedCurve: "P-256"},
          true,
          ["sign", "verify"])
           .then(keys => {
              this._private_key = keys.privateKey;
              this._public_key = keys.publicKey;
              console.info(this.lang.info.OK_VAPID_KEYS);
              return keys;
           })
           .catch(fail => {
               console.error(this.lang.errs.ERR_VAPID_KEY, fail);
               throw(fail);
               });
    }

    export_public_raw() {
        /* Export an ASN1 RAW key pair.
         *
         * This is used in the Crypto-Key header.
         *
         * NOTE: Chrome 52 does not yet support RAW keys
         */
        return webCrypto.exportKey('jwk', this._public_key)
            .then( key => {
                return this.mzcc.toUrlBase64("\x04" +
                    this.mzcc.fromUrlBase64(key.x) +
                    this.mzcc.fromUrlBase64(key.y))
            })
            .catch(err => {
                console.error("public raw format", err);
                throw err;
            })
    }

    import_public_raw(raw) {
        /* Import an ASN1 RAW public key pair.
         *
         * :param raw: a URL safe base64 encoded rendition of the RAW key.
         * :returns: a promise from the imported key.
         */
        if (typeof(raw) == "string") {
            raw = this.mzcc.strToArray(this.mzcc.fromUrlBase64(raw));
        }
        let err = new Error(this.lang.errs.ERR_PUB_KEY);

        // Raw is supposed to start with a 0x04, but some libraries don't. sigh.
        if (raw.length == 65 && raw[0] != 4) {
            throw err;
        }

        raw= raw.slice(-64);
        let x = this.mzcc.toUrlBase64(String.fromCharCode.apply(null,
             raw.slice(0,32)));
        let y = this.mzcc.toUrlBase64(String.fromCharCode.apply(null,
             raw.slice(32,64)));

        // Convert to a JWK and import it.
        let jwk = {
            crv: "P-256",
            ext: true,
            key_ops: ["verify"],
            kty: "EC",
            x: x,
            y, y
        };

        return webCrypto.importKey('jwk', jwk, 'ECDSA', true, ["verify"])
            .then(k => this._public_key = k)
    }



    sign(claims) {
        /* Sign a claims object and return the headers that can be used to
         * decrypt the string.
         *
         * :param claims: An object containing the VAPID claims.
         * :returns: a promise containing an object identifying the headers
         * and values to include to specify VAPID auth.
        */
        if (! claims) {
            claims = this._claims;
        }
        if (this._public_key == "") {
            throw new Error(this.lang.errs.ERR_NO_KEYS);
        }
        if (! claims.hasOwnProperty("exp")) {
            claims.exp = parseInt(Date.now()*.001) + 86400;
        }
        if (! claims.hasOwnProperty("sub")) {
            throw new Error(this.lang.errs.ERR_CLAIM_MIS, "sub");
        }
        let alg = {name:"ECDSA", namedCurve: "P-256", hash:{name:"SHA-256"}};
        let headStr = this.mzcc.toUrlBase64(
            JSON.stringify({typ:"JWT",alg:"ES256"}));
        let claimStr = this.mzcc.toUrlBase64(
            JSON.stringify(claims));
        let content = headStr + "." + claimStr;
        let signatory = this.mzcc.strToArray(content);
        return webCrypto.sign(
            alg,
            this._private_key,
            signatory)
            .then(signature => {
                let sig = this.mzcc.toUrlBase64(
                    this.mzcc.arrayToStr(signature));
                /* The headers consist of the constructed JWT as the
                 * "authorization" and the raw Public key as the p256ecdsa
                 * element of "Crypto-Key"
                 * Note that Crypto-Key can contain many elements, separated
                 * by a ",".i You may need to append this value to an existing
                 * "Crypto-Key" header value.
                 *
                 *
                 */
                return this.export_public_raw()
                    .then( pubKey => {
                        return {
                            authorization: "WebPush " + content + "." + sig,
                            "crypto-key": "p256ecdsa=" + pubKey,
                            publicKey: pubKey,
                        }
                    })
            })
            .catch(err => {
                console.error(this.lang.errs.ERR_SIGN, err);
            })
    }

    verify(token, public_key=null) {
        /* Verify a VAPID token.
         *
         * Token is the Authorization Header, Public Key is the Crypto-Key
         * header.
         *
         * :param token: the Authorization header bearer token
         */

        // Ideally, just the bearer token, Cheat a little to be nice to the dev.
        scheme = token.toLowerCase().split(" ")[0]
        if (scheme == "bearer" || scheme == "webpush") {
            token = token.split(" ")[1];
        }

        // Again, ideally, just the p256ecdsa token.
        if (public_key != null) {

            if (public_key.search('p256ecdsa') > -1) {
                let sc = /p256ecdsa=([^;,]+)/i;
                public_key = sc.exec(public_key)[1];
            }

            // If there's no public key already defined, load the public_key
            // and try again.
            return this.import_public_raw(public_key)
                .then(key => {
                    this._public_key = key;
                    return this.verify(token);
                })
                .catch(err => {
                    console.error("Verify error", err);
                    throw err;
                });
        }
        if (this._public_key == "") {
            throw new Error(this.lang.errs.ERR_NO_KEYS);
        }

        let alg = {name: "ECDSA", namedCurve: "P-256",
                   hash: {name: "SHA-256" }};
        let items = token.split('.');
        let signature;
        let key;
        try {
            signature = this.mzcc.strToArray(
                this.mzcc.fromUrlBase64(items[2]));
        } catch (err) {
            throw new Error(this.lang.errs.ERR_VERIFY_SG + err.message);
        }
        try {
            key = this.mzcc.strToArray(this.mzcc.fromUrlBase64(items[1]));
        } catch (err) {
            throw new Error(this.lang.errs.ERR_VERIFY_KE + err.message);
        }
        let content = items.slice(0,2).join('.');
        let signatory = this.mzcc.strToArray(content);
        return webCrypto.verify(
            alg,
            this._public_key,
            signature,
            signatory)
           .then(valid => {
               if (valid) {
                   return JSON.parse(
                        String.fromCharCode.apply(
                            null,
                            this.mzcc.strToArray(
                                this.mzcc.fromUrlBase64(items[1]))))
               }
               throw new Error(this.lang.errs.ERR_SIGNATURE);
           })
           .catch(err => {
               console.error(this.lang.errs.ERR_VERIFY, err);
               throw new Error (this.lang.errs.ERR_VERIFY + ": " + err.message);
           });
    }

    /* The following are for the Dashboard key ownership validation steps.
     * The Mozilla WebPush dashboard will provide a token, which you will
     * need to sign with your Vapid Private Key. Paste the signature back
     * into the dashboard to validate that you own the key.
     */

    validate(string) {
        /* Sign the token for the developer Dashboard.
         *
         * The Developer Dashboard requires that a token be signed using
         * the VAPID private key in order to show that a user actually
         * owns their public key.
         *
         * :param string: The token provided by the Dashboard Validate
         *  function
         * :returns: the signature value to paste back into the Dashboard.
         */
        let alg = {name:"ECDSA", namedCurve: "P-256", hash:{name:"SHA-256"}};
        let t2v = this.mzcc.strToArray(string);
        return webCrypto.sign(alg, this._private_key, t2v)
            .then(signed => {
                let sig = this.mzcc.toUrlBase64(this.mzcc.arrayToStr(signed));
                return sig;
            });
    }

    validateCheck(sig, string) {
        /* verify a given signature string matches.
         *
         * This function is used for testing only.
         *
         * :param sig: The signature value generated by validate()
         * :param string: The token string originally passed to validate
         * :returns: Boolean indicating successful verification.
         */
        let alg = {name: "ECDSA", namedCurve: "P-256", hash:{name:"SHA-256"}};
        let vsig = this.mzcc.strToArray(this.mzcc.fromUrlBase64(sig));
        let t2v = this.mzcc.strToArray(this.mzcc.fromUrlBase64(string));
        return webCrypto.verify(alg, this._public_key, vsig, t2v);
    }
}
