import BN from 'bn.js';
export class Signature {
    r = new BN(0);
    s = new BN(0);
    recoveryParam = null;
    constructor(sig, enc) {
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
        this.r = new BN(sig.r);
        // @ts-ignore("BN can use readonly number[]")
        this.s = new BN(sig.s);
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
        this.r = new BN(r);
        this.s = new BN(s);
    }
}
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
    place = 0;
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2lnbmF0dXJlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9zaWduYXR1cmUudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsT0FBTyxFQUFFLE1BQU0sT0FBTyxDQUFDO0FBR3ZCLE1BQU0sT0FBTyxTQUFTO0lBQ3BCLENBQUMsR0FBTyxJQUFJLEVBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUNsQixDQUFDLEdBQU8sSUFBSSxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDbEIsYUFBYSxHQUFrQixJQUFJLENBQUM7SUFDcEMsWUFBWSxHQUFtQixFQUFFLEdBQVc7UUFDMUMsSUFBSSxHQUFHLFlBQVksU0FBUyxFQUFFO1lBQzVCLE9BQU8sR0FBRyxDQUFDO1NBQ1o7UUFFRCxJQUNFLEdBQUcsWUFBWSxLQUFLO1lBQ3BCLEdBQUcsWUFBWSxVQUFVO1lBQ3pCLE9BQU8sR0FBRyxLQUFLLFFBQVEsRUFDdkI7WUFDQSxJQUFJLENBQUMsU0FBUyxDQUFDLEdBQUcsRUFBRSxHQUFHLENBQUMsQ0FBQztZQUN6QixPQUFPO1NBQ1I7UUFDRCw2Q0FBNkM7UUFDN0MsSUFBSSxDQUFDLENBQUMsR0FBRyxJQUFJLEVBQUUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUM7UUFDdkIsNkNBQTZDO1FBQzdDLElBQUksQ0FBQyxDQUFDLEdBQUcsSUFBSSxFQUFFLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDO1FBQ3ZCLElBQUksQ0FBQyxhQUFhLEdBQUcsR0FBRyxDQUFDLGFBQWEsSUFBSSxJQUFJLENBQUM7SUFDakQsQ0FBQztJQUlELEtBQUssQ0FBQyxHQUFXO1FBQ2YsSUFBSSxDQUFDLEdBQUcsSUFBSSxDQUFDLENBQUMsQ0FBQyxPQUFPLEVBQUUsQ0FBQztRQUN6QixJQUFJLENBQUMsR0FBRyxJQUFJLENBQUMsQ0FBQyxDQUFDLE9BQU8sRUFBRSxDQUFDO1FBQ3pCLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FB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