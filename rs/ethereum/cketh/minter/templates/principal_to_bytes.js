/**
 * Converts a principal into a fixed 32-byte representation suitable for calling Ethereum smart contracts.
 * @param {string} text The textual representation of a principal.
 * @return {string} A 32-byte hex-encoded byte string.
 */
function principalToBytes32(text) {
    /**
     * Decodes a base32-encoded string into a byte array.
     * @param {string} text A base-32 encoded string.
     * @return {Array<number>} A byte array.
     */
    function base32Decode(text) {
        const ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
        let width = 0;
        let acc = 0;
        let bytes = [];
        for (let i = 0; i < text.length; i++) {
            let c = text.charAt(i);
            let b = ALPHABET.indexOf(c);
            if (b == -1) throw Error("Invalid principal: unexpected lowercase base32 character: " + c);
            acc = (acc << 5) + b;
            width += 5;
            if (width >= 8) {
                bytes.push(acc >> (width - 8));
                acc &= (1 << (width - 8)) - 1;
                width -= 8;
            }
        }
        if (acc > 0) {
            throw Error("Invalid principal: non-zero padding");
        }
        return bytes;
    }

    /**
     * Appends a hex representation of a number to string.
     * @param {string} s A string to append the hex to.
     * @param {number} b A byte.
     * @return {string} An updated string.
     */
    function appendHexByte(s, b) {
        s += ((b >> 4) & 0x0f).toString(16);
        s += (b & 0x0f).toString(16);
        return s;
    }

    /**
     * Encodes a byte array as Ethereum data hex (staring with 0x).
     * @param {Array<number>} bytes A byte array.
     * @return {string} A hex string.
     */
    function bytes32Encode(bytes) {
        let n = bytes.length;
        let s = "0x";
        s = appendHexByte(s, n);
        for (let i = 0; i < bytes.length; i++) {
            s = appendHexByte(s, bytes[i]);
        }
        for (let i = 0; i < 31 - bytes.length; i++) {
            s += "00";
        }
        return s;
    }

    let ungroup = text.replace(/-/g, "");
    let rawBytes = base32Decode(ungroup);
    if (rawBytes.length < 4) {
        throw Error("Invalid principal: too short");
    }
    if (rawBytes.length > 33) {
        throw Error("Invalid principal: too long");
    }
    return bytes32Encode(rawBytes.slice(4));
}