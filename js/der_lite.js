'use strict';

class DERLite{
    constructor() {}

    /* Simplified DER export and import is provided because a large number of
     * libraries and languages understand DER as a key exchange and storage
     * format. DER is NOT required for VAPID, however, the key you may
     * generate here (or in a different library) may be in this format.
     *
     * A fully featured DER library is available at
     * https://github.com/indutny/asn1.js
     */

    export_private_der(key) {
        /* Generate a DER sequence.
         *
         * This can be read in via something like
         * python's
         * ecdsa.keys.SigningKey
         *     .from_der(base64.urlsafe_b64decode("MHc..."))
         *
         * :param key: CryptoKey containing private key info
         */
        return webCrypto.exportKey("jwk", key)
            .then(k => {
                // verifying key
                let xv = mzcc.fromUrlBase64(k.x);
                let yv = mzcc.fromUrlBase64(k.y);
                // private key
                let dv = mzcc.fromUrlBase64(k.d);

                // verifying key (public)
                let vk = '\x00\x04' + xv + yv;
                // \x02 is integer
                let int1 = '\x02\x01\x01'; // integer 1
                // \x04 is octet string
                let dvstr = '\x04' + mzcc.chr(dv.length) + dv;
                let curve_oid = "\x06\x08" +
                    "\x2a\x86\x48\xce\x3d\x03\x01\x07";
                // \xaX is a construct, low byte is order.
                let curve_oid_const = '\xa0' + mzcc.chr(curve_oid.length) +
                    curve_oid;
                // \x03 is a bitstring
                let vk_enc = '\x03' + mzcc.chr(vk.length) + vk;
                let vk_const = '\xa1' + mzcc.chr(vk_enc.length) + vk_enc;
                // \x30 is a sequence start.
                let seq = int1 + dvstr + curve_oid_const + vk_const;
                let rder = "\x30" + mzcc.chr(seq.length) + seq;
                return mzcc.toUrlBase64(rder);
            })
            .catch(err => console.error(err))
    }

    import_private_der(der_str) {
        /* Import a Private Key stored in DER format. This allows a key
         * to be generated outside of this script.
         *
         * :param der_str: URL safe base64 formatted DER string.
         * :returns: Promise containing the imported private key
         */
        let der = mzcc._strToArray(mzcc.fromUrlBase64(der_str));
        // quick guantlet to see if this is a valid DER
        let cmp = new Uint8Array([2,1,1,4]);
        if (der[0] != 48 ||
            ! der.slice(2, 6).every(function(v, i){return cmp[i] == v})){
            throw new Error("Invalid import key")
        }
        let dv = der.slice(7, 7+der[6]);
        // HUGE cheat to get the x y values
        let xv = der.slice(-64, -32);
        let yv = der.slice(-32);
        let key_ops = ['sign'];

        let jwk = {
           crv: "P-256",
           ext: true,
           key_ops: key_ops,
           kty: "EC",
           x: mzcc.toUrlBase64(String.fromCharCode.apply(null, xv)),
           y: mzcc.toUrlBase64(String.fromCharCode.apply(null, yv)),
           d: mzcc.toUrlBase64(String.fromCharCode.apply(null, dv)),
        };

        console.debug(JSON.stringify(jwk));
        return webCrypto.importKey('jwk', jwk, 'ECDSA', true, key_ops);
    }

    export_public_der(key) {
        /* Generate a DER sequence containing just the public key info.
         *
         * :param key: CryptoKey containing public key information
         * :returns: a URL safe base64 encoded string containing the
         *   public key
         */
        return webCrypto.exportKey("jwk", key)
            .then(k => {
                // raw keys always begin with a 4
                let xv = mzcc._strToArray(mzcc.fromUrlBase64(k.x));
                let yv = mzcc._strToArray(mzcc.fromUrlBase64(k.y));

                let point = "\x00\x04" +
                    String.fromCharCode.apply(null, xv) +
                    String.fromCharCode.apply(null, yv);
                window.Kpoint = point;
                // a combination of the oid_ecPublicKey + p256 encoded oid
                let prefix = "\x30\x13" +  // sequence + length
                    "\x06\x07" + "\x2a\x86\x48\xce\x3d\x02\x01" +
                    "\x06\x08" + "\x2a\x86\x48\xce\x3d\x03\x01\x07"
                let encPoint = "\x03" + mzcc.chr(point.length) + point
                let rder = "\x30" + mzcc.chr(prefix.length + encPoint.length) +
                    prefix + encPoint;
                let der = mzcc.toUrlBase64(rder);
                return der;
            });
    }

    import_public_der(derArray) {
        /* Import a DER formatted public key string.
         *
         * The Crypto-Key p256ecdsa=... key is such a thing.
         * Returns a promise containing the public key.
         *
         * :param derArray: the DER array containing the public key.
         *  NOTE: This may also be a URL safe base64 encoded version
         *  of the DER array.
         * :returns: A promise containing the imported public key.
         *
         */
        if (typeof(derArray) == "string") {
            derArray = mzcc._strToArray(mzcc.fromUrlBase64(derArray));
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
        let x = mzcc.toUrlBase64(String.fromCharCode
                .apply(null, derArray.slice(27, 27+32)));
        let y = mzcc.toUrlBase64(String.fromCharCode
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

    }
}

