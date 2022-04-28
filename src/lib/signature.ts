import BN from 'bn.js';
import { SignatureInput } from 'elliptic';

export class Signature {
  r: BN = new BN(0);
  s: BN = new BN(0);
  recoveryParam: number | null = null;
  constructor(sig: SignatureInput, enc?: 'hex') {
    if (sig instanceof Signature) {
      return sig;
    }

    if (
      sig instanceof Array ||
      sig instanceof Uint8Array ||
      typeof sig === 'string'
    ) {
      this.importDER(sig, enc);
      return;
    }
    // @ts-ignore("BN can use readonly number[]")
    this.r = new BN(sig.r);
    // @ts-ignore("BN can use readonly number[]")
    this.s = new BN(sig.s);
    this.recoveryParam = sig.recoveryParam || null;
  }

  toDER(): number[];
  toDER(enc: 'hex'): string;
  toDER(enc?: 'hex'): number[] | string {
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

  private importDER(
    data: string | Uint8Array | ReadonlyArray<number>,
    enc?: 'hex'
  ) {
    const der =
      typeof data === 'string' ? Buffer.from(data, enc) : Buffer.from(data);
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
    if (len < 0 || len + p.place > data.length) return;

    let r = der.slice(p.place, len + p.place);
    p.place += len;

    // s
    if (der[p.place++] !== 0x02) {
      return;
    }

    len = getLength(der, p);
    if (len < 0 || len + p.place !== data.length) return;

    let s = der.slice(p.place, len + p.place);
    p.place += len;

    if (r[0] === 0) {
      if (r[1] & 0x80) {
        r = r.slice(1);
      } else {
        return;
      }
    }
    if (s[0] === 0) {
      if (s[1] & 0x80) {
        s = s.slice(1);
      } else {
        return;
      }
    }

    this.r = new BN(r);
    this.s = new BN(s);
  }
}

function rmPadding(buf: number[]): number[] {
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
function constructLength(arr: number[], len: number) {
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

function getLength(buf: Buffer, p: Position): number {
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
