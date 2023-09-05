function principalToBytes32(text) {
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

    function appendHexByte(s, b) {
        s += ((b >> 4) & 0x0f).toString(16);
        s += (b & 0x0f).toString(16);
        return s;
    }

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

    let ungroup = text.replaceAll("-", "");
    let rawBytes = base32Decode(ungroup);
    if (rawBytes.length < 4) {
        throw Error("Invalid principal: too short");
    }
    if (rawBytes.length > 33) {
        throw Error("Invalid principal: too long");
    }
    return bytes32Encode(rawBytes.slice(4));
}