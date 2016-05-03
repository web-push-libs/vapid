class MozCommon {

    constructor() {
    }

    ord(c){
        /* return an ordinal for a character
        */
        return c.charCodeAt(0);
    }

    chr(c){
        /* return a character for a given ordinal
        */
        return String.fromCharCode(c);
    }

    toUrlBase64(data) {
        /* Convert a binary array into a URL safe base64 string
        */
        return btoa(data)
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=/g, "")
    }

    fromUrlBase64(data) {
        /* return a binary array from a URL safe base64 string
        */
        return atob((data + "====".substr(data.length % 4))
            .replace(/\-/g, "+")
            .replace(/\_/g, "/"));
    }

    _strToArray(str) {
        /* convert a string into a ByteArray
         *
         * TextEncoders would be faster, but have a habit of altering
         * byte order
         */
        let split = str.split("");
        let reply = new Uint8Array(split.length);
        for (let i in split) {
            reply[i] = this.ord(split[i]);
        }
        return reply;
    }

    _arrayToStr(array) {
        /* convert a ByteArray into a string
         */
        return String.fromCharCode.apply(null, new Uint8Array(array));
    }

    rawToJWK(raw, ops) {
    /* convert a URL safe base64 raw key to jwk format
    */
        if (typeof(raw) == "string") {
            raw = this._strToArray(this.fromUrlBase64(raw));
        }
        // Raw is supposed to start with a 0x04, but some libraries don't. sigh.
        if (raw.length == 65 && raw[0] != 4) {
            throw new Error('ERR_PUB_KEY');
        }

        raw= raw.slice(-64);
        let x = this.toUrlBase64(String.fromCharCode.apply(null,
            raw.slice(0,32)));
        let y = this.toUrlBase64(String.fromCharCode.apply(null,
            raw.slice(32,64)));

        // Convert to a JWK and import it.
        let jwk = {
            crv: "P-256",
            ext: true,
            key_ops: ops,
            kty: "EC",
            x: x,
            y, y
        };

        return jwk
    }

    JWKToRaw(jwk) {
        /* Convert a JWK object to a "raw" URL Safe base64 string
        */
        xv = this.fromUrlBase64(jwk.x);
        yv = this.fromUrlBase64(jwk.y);
        return this.toUrlBase64("\x04" + xv + yv);
    }
}

