
function decode(str) {
    /* Take a URL Safe base64 string and convert to a Uint8 Byte Array.
     *
     * See https://en.wikipedia.org/wiki/Base64 for characters exchanges
     */
    cstr = atob(str.replace('-', '+').replace('_', '/'));
    arr = new Uint8Array(cstr.length)
    for (i=0; i<cstr.length;i++) {
        arr[i] = cstr.charCodeAt(i);
    }
    return arr;
}

