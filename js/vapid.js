/* Javascript VAPID library.
 *
 */

'use strict';

var webCrypto = window.crypto.subtle;

function ord(c){
    /* return an ordinal for a character */
    return c.charCodeAt(0);
}

function chr(c){
    /* return a character for a given ordinal */
    return String.fromCharCode(c);
}

var vapid = {
    /* English:US */
    enus: {
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
    },

    _private_key:  "",
    _public_key: "",

    /* Generate and verify a VAPID token */
    generate_keys: function() {
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
           })
           .catch(fail => {
               console.error(this.lang.errs.ERR_VAPID_KEY, fail);
               });
    },

    _str_to_array: function(str) {
        /* convert a string into a ByteArray
         *
         * TextEncoders would be faster, but have a habit of altering
         * byte order
         */
        let split = str.split("");
        let reply = new Uint8Array(split.length);
        for (let i in split) {
            reply[i] = String.charCodeAt(split[i]);
        }
        return reply;
    },

    _array_to_str: function(array) {
        /* convert a ByteArray into a string
         */
        return String.fromCharCode.apply(null, new Uint8Array(array));
    },

    toUrlBase64: function(data) {
        /* Convert a binary array into a URL safe base64 string */
        return btoa(data)
            .replace(/\+/g, "-")
            .replace(/\//g, "_");
    },

    fromUrlBase64: function(data) {
        /* return a binary array from a URL safe base64 string */
        return this._str_to_array(atob(data
                                       .replace(/\-/g, "+")
                                       .replace(/\_/g, "/")));
    },

    /* A fully featured DER library is available at
     * https://github.com/indutny/asn1.js
     */

    export_private_der: function() {
        /* Generate a DER sequence. This can be read in via
         * something like python's
         * ecdsa.keys.SigningKey
         *     .from_der(base64.urlsafe_b64decode("MHc..."))
         */
        return webCrypto.exportKey("jwk", this._private_key)
            .then(k => {
                // verifying key
                let xv = String.fromCharCode.apply(null, this.fromUrlBase64(k.x));
                let yv = String.fromCharCode.apply(null, this.fromUrlBase64(k.y));
                // private key
                let dv = String.fromCharCode.apply(null, this.fromUrlBase64(k.d));

                // verifying key (public)
                let vk = '\x00\x04' + xv + yv;
                // \x02 is integer
                let int1 = '\x02\x01\x01'; // integer 1
                // \x04 is octet string
                let dvstr = '\x04' + chr(dv.length) + dv;
                let curve_oid = "\x06\x08" +
                    "\x2a\x86\x48\xce\x3d\x03\x01\x07";
                // \xaX is a construct, low byte is order.
                let curve_oid_const = '\xa0' + chr(curve_oid.length) +
                    curve_oid;
                // \x03 is a bitstring
                let vk_enc = '\x03' + chr(vk.length) + vk;
                let vk_const = '\xa1' + chr(vk_enc.length) + vk_enc;
                // \x30 is a sequence start.
                let seq = int1 + dvstr + curve_oid_const + vk_const;
                let rder = "\x30" + chr(seq.length) + seq;
                return this.toUrlBase64(rder);
            })
            .catch(err => console.error(err))
    },

    export_public_der: function () {
        /* Generate a DER sequence containing the public key info */
        return webCrypto.exportKey("jwk", this._public_key)
            .then(k => {
                // raw keys always begin with a 4
                let xv = this.fromUrlBase64(k.x);
                let yv = this.fromUrlBase64(k.y);

                let point = "\x00\x04" +
                    String.fromCharCode.apply(null, xv) +
                    String.fromCharCode.apply(null, yv);
                window.Kpoint = point;
                // a combination of the oid_ecPublicKey + p256 encoded oid
                let prefix = "\x30\x13" +  // sequence + length
                    "\x06\x07" + "\x2a\x86\x48\xce\x3d\x02\x01" +
                    "\x06\x08" + "\x2a\x86\x48\xce\x3d\x03\x01\x07"
                let encPoint = "\x03" + chr(point.length) + point
                let rder = "\x30" + chr(prefix.length + encPoint.length) +
                    prefix + encPoint;
                let der = this.toUrlBase64(rder);
                return der;
            });
    },

    export_public_raw: function() {
        return webCrypto.exportKey('raw', this._public_key)
            .then( key => {
                return this.toUrlBase64(this._array_to_str(key));
            })
    },

    import_public_raw: function(raw) {
        if (typeof(raw) == "string") {
            raw = this.fromUrlBase64(raw);
        }
        let err = new Error(this.lang.errs.ERR_PUB_KEY);

        // Raw is supposed to start with a 0x04, but some libraries don't. sigh.
        if (raw.length == 65 && raw[0] != 4) {
            throw err;
        }

        raw= raw.slice(-64);
        let x = this.toUrlBase64(String.fromCharCode.apply(null, raw.slice(0,32)));
        let y = this.toUrlBase64(String.fromCharCode.apply(null, raw.slice(32,64)));

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
    },


    import_public_der: function(derArray) {
        /* Import a DER formatted public key string.
         *
         * The Crypto-Key p256ecdsa=... key is such a thing.
         * Returns a promise containing the public key.
         */
        if (typeof(derArray) == "string") {
            derArray = this.fromUrlBase64(derArray);
        }
        /* Super light weight public key import function */
        let err = new Error(this.lang.errs.ERR_PUB_D_KEY);
        // Does the record begin with "\x30"
        if (derArray[0] != 48) { throw err}
        // is this an ECDSA record? (looking for \x2a and \x86
        if (derArray[6] != 42 && derArray[7] != 134) { throw err}
        if (derArray[15] != 42 && derArray[16] != 134) { throw err}
        // Public Key Record usually beings @ offset 23.
        if (derArray[23] != 3 && derArray[24] != 40 &&
                derArray[25] != 0 && derArray[26] != 4) {
            throw err;
        }
        // pubkey offset starts at byte 25
        let x = this.toUrlBase64(String.fromCharCode
                .apply(null, derArray.slice(27, 27+32)));
        let y = this.toUrlBase64(String.fromCharCode
                .apply(null, derArray.slice(27+32, 27+64)));

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

    },


    sign: function(claims) {
        /* Sign a claims object and return the headers that can be used to decrypt the string.
         *
         * Returns a promise containing an object identifying the headers and values to include
         * to specify VAPID auth.
        */
        if (this._public_key == "") {
            throw new Error(this.lang.errs.ERR_NO_KEYS);
        }
        if (!claims.hasOwnProperty("exp")) {
            claims.exp = parseInt(Date.now()*.001) + 86400;
        }
        ["sub","aud"].forEach(function(key){
            if (! claims.hasOwnProperty(key)) {
                throw new Error(this.lang.errs.ERR_CLAIM_MIS, key);
            }
        })
        let alg = {name:"ECDSA", namedCurve: "P-256", hash:{name:"SHA-256"}};
        let headStr = btoa(JSON.stringify({typ:"JWT",alg:"ES256"}));
        let claimStr = btoa(JSON.stringify(claims));
        let content = headStr + "." + claimStr;
        let signatory = this._str_to_array(content);
        return webCrypto.sign(
            alg,
            this._private_key,
            signatory)
            .then(signature => {
                let sig = this.toUrlBase64(this._array_to_str(signature));
                /* The headers consist of the constructed JWT as the "authorization"
                 * and the raw Public key as the p256ecdsa element of "Crypto-Key"
                 * Note that Crypto-Key can contain many elements, separated by a ","
                 * You may need to append this value to an existing "Crypto-Key"
                 * header value.
                 */
                return webCrypto.exportKey('raw', this._public_key)
                    .then( key => {
                        let pubKey = this.toUrlBase64(this._array_to_str(key));
                        return {
                            authorization: "Bearer " + content + "." + sig,
                            "crypto-key": "p256ecdsa=" + pubKey,
                            publicKey: pubKey,
                        }
                    })
            })
            .catch(err => {
                console.error(this.lang.errs.ERR_SIGN, err);
            })
    },

    validate: function(string) {
        /* Sign the token for the developer Dashboard */
        let alg = {name:"ECDSA", namedCurve: "P-256", hash:{name:"SHA-256"}};
        let t2v = this._str_to_array(string);
        return webCrypto.sign(alg, this._private_key, t2v)
            .then(signed => {
                let sig = this.toUrlBase64(this._array_to_str(signed));
                return sig;
            });
    },

    validateCheck: function(sig, string) {
        /* verify a given signature string matches */
        let alg = { name: "ECDSA", namedCurve: "P-256", hash:{name:"SHA-256"}};
        let vsig = this.fromUrlBase64(sig);
        let t2v = this.fromUrlBase64(string);
        return webCrypto.verify(alg, this._public_key, vsig, t2v);
    },

    verify: function(token, public_key=null) {
        /* Verify a VAPID token.
         *
         * Token is the Authorization Header, Public Key is the Crypto-Key header.
        */

        // Ideally, just the bearer token, Cheat a little to be nice to the dev.
        if (token.search("earer ") > -1) {
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

        let alg = { name: "ECDSA", namedCurve: "P-256", hash: {name: "SHA-256" }};
        let items = token.split('.');
        let signature;
        let key;
        try {
            signature = this.fromUrlBase64(items[2]);
        } catch (err) {
            throw new Error(this.lang.errs.ERR_VERIFY_SG + err.message);
        }
        try {
            key = this.fromUrlBase64(items[1]);
        } catch (err) {
            throw new Error(this.lang.errs.ERR_VERIFY_KE + err.message);
        }
        let content = items.slice(0,2).join('.');
        let signatory = this._str_to_array(content);
        return webCrypto.verify(
            alg,
            this._public_key,
            signature,
            signatory)
           .then(valid => {
               if (valid) {
                   return JSON.parse(String.fromCharCode
                                        .apply(null, this.fromUrlBase64(items[1])))
               }
               throw new Error(this.lang.errs.ERR_SIGNATURE);
           })
           .catch(err => {
               console.error(this.lang.errs.ERR_VERIFY, err);
               throw new Error (this.lang.errs.ERR_VERIFY + ": " + err.message);
           });
    }
}

vapid.lang = vapid.enus;
