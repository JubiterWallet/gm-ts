"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Signature = void 0;
const bn_js_1 = __importDefault(require("bn.js"));
class Signature {
    constructor(sig, enc) {
        this.r = new bn_js_1.default(0);
        this.s = new bn_js_1.default(0);
        this.recoveryParam = null;
        if (sig instanceof Signature) {
            return sig;
        }
        if (sig instanceof Array ||
            sig instanceof Uint8Array ||
            typeof sig === 'string') {
            this.importDER(sig, enc);
            return;
        }
        // @ts-ignore("BN can use readonly number[]")
        this.r = new bn_js_1.default(sig.r);
        // @ts-ignore("BN can use readonly number[]")
        this.s = new bn_js_1.default(sig.s);
        this.recoveryParam = sig.recoveryParam || null;
    }
    toDER(enc) {
        let r = this.r.toArray();
        let s = this.s.toArray();
        if (r[0] & 0x80) {
            r = [0].concat(r);
        }
        if (s[0] & 0x80) {
            s = [0].concat(s);
        }
        r = rmPadding(r);
        s = rmPadding(s);
        let rs = [0x02];
        constructLength(rs, r.length);
        rs = rs.concat(r);
        rs.push(0x02);
        constructLength(rs, s.length);
        rs = rs.concat(s);
        let der = [0x30];
        constructLength(der, rs.length);
        der = der.concat(rs);
        return enc ? Buffer.from(der).toString(enc) : der;
    }
    importDER(data, enc) {
        const der = typeof data === 'string' ? Buffer.from(data, enc) : Buffer.from(data);
        const p = new Position();
        // sequence
        if (der[p.place++] != 0x30) {
            return;
        }
        let len = getLength(der, p);
        if (len < 0) {
            return;
        }
        if (len + p.place !== data.length) {
            return;
        }
        // r
        if (der[p.place++] !== 0x02) {
            return;
        }
        len = getLength(der, p);
        if (len < 0 || len + p.place > data.length)
            return;
        let r = der.slice(p.place, len + p.place);
        p.place += len;
        // s
        if (der[p.place++] !== 0x02) {
            return;
        }
        len = getLength(der, p);
        if (len < 0 || len + p.place !== data.length)
            return;
        let s = der.slice(p.place, len + p.place);
        p.place += len;
        if (r[0] === 0) {
            if (r[1] & 0x80) {
                r = r.slice(1);
            }
            else {
                return;
            }
        }
        if (s[0] === 0) {
            if (s[1] & 0x80) {
                s = s.slice(1);
            }
            else {
                return;
            }
        }
        this.r = new bn_js_1.default(r);
        this.s = new bn_js_1.default(s);
    }
}
exports.Signature = Signature;
function rmPadding(buf) {
    let i = 0;
    const len = buf.length - 1;
    while (!buf[i] && !(buf[i + 1] & 0x80) && i < len) {
        i++;
    }
    if (i === 0) {
        return buf;
    }
    return buf.slice(i);
}
function constructLength(arr, len) {
    if (len < 0x80) {
        arr.push(len);
        return;
    }
    let octets = 1 + ((Math.log(len) / Math.LN2) >>> 3);
    arr.push(octets | 0x80);
    while (--octets) {
        arr.push((len >>> (octets << 3)) & 0xff);
    }
    arr.push(len);
}
class Position {
    constructor() {
        this.place = 0;
    }
}
function getLength(buf, p) {
    const initial = buf[p.place++];
    if (!(initial & 0x80)) {
        return initial;
    }
    const octetLen = initial & 0xf;
    // Indefinite length or overflow
    if (octetLen === 0 || octetLen > 4) {
        return -1;
    }
    let val = 0;
    let off = p.place;
    for (let i = 0; i < octetLen; i++, off++) {
        val <<= 8;
        val |= buf[off];
        val >>>= 0;
    }
    // Leading zeroes
    if (val <= 0x7f) {
        return -1;
    }
    p.place = off;
    return val;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2lnbmF0dXJlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9zaWduYXR1cmUudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQUEsa0RBQXVCO0FBR3ZCLE1BQWEsU0FBUztJQUlwQixZQUFZLEdBQW1CLEVBQUUsR0FBVztRQUg1QyxNQUFDLEdBQU8sSUFBSSxlQUFFLENBQUMsQ0FBQyxDQUFDLENBQUM7UUFDbEIsTUFBQyxHQUFPLElBQUksZUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDO1FBQ2xCLGtCQUFhLEdBQWtCLElBQUksQ0FBQztRQUVsQyxJQUFJLEdBQUcsWUFBWSxTQUFTLEVBQUU7WUFDNUIsT0FBTyxHQUFHLENBQUM7U0FDWjtRQUVELElBQ0UsR0FBRyxZQUFZLEtBQUs7WUFDcEIsR0FBRyxZQUFZLFVBQVU7WUFDekIsT0FBTyxHQUFHLEtBQUssUUFBUSxFQUN2QjtZQUNBLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxFQUFFLEdBQUcsQ0FBQyxDQUFDO1lBQ3pCLE9BQU87U0FDUjtRQUNELDZDQUE2QztRQUM3QyxJQUFJLENBQUMsQ0FBQyxHQUFHLElBQUksZUFBRSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQztRQUN2Qiw2Q0FBNkM7UUFDN0MsSUFBSSxDQUFDLENBQUMsR0FBRyxJQUFJLGVBQUUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUM7UUFDdkIsSUFBSSxDQUFDLGFBQWEsR0FBRyxHQUFHLENBQUMsYUFBYSxJQUFJLElBQUksQ0FBQztJQUNqRCxDQUFDO0lBSUQsS0FBSyxDQUFDLEdBQVc7UUFDZixJQUFJLENBQUMsR0FBRyxJQUFJLENBQUMsQ0FBQyxDQUFDLE9BQU8sRUFBRSxDQUFDO1FBQ3pCLElBQUksQ0FBQyxHQUFHLElBQUksQ0FBQyxDQUFDLENBQUMsT0FBTyxFQUFFLENBQUM7UUFDekIsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUcsSUFBSSxFQUFF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