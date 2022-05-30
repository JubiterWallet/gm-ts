import { HMACDRBG } from '@stablelib/hmac-drbg';
import { BN } from 'bn.js';
import { BNInput, curve, curves, ec, SignatureInput } from 'elliptic';
import { sha256 } from 'hash.js';

import { Signature } from './signature';

export class SM2 extends ec {
  constructor() {
    super(
      new curves.PresetCurve({
        type: 'short',
        prime: null,
        p: 'FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF',
        a: 'FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC',
        b: '28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93',
        n: 'FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123',
        hash: sha256,
        gRed: false,
        g: [
          '32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7',
          'BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0',
        ],
      })
    );
  }

  sign(
    msg: BNInput,
    key: Buffer | ec.KeyPair,
    enc: string,
    options?: ec.SignOptions
  ): ec.Signature;
  sign(
    msg: BNInput,
    key: Buffer | ec.KeyPair,
    options?: ec.SignOptions
  ): ec.Signature;

  sign(msg: BNInput, key: Buffer | ec.KeyPair, ...options: any): ec.Signature {
    let [enc, opt] = options;
    if (typeof enc === 'object') {
      opt = enc;
      enc = null;
    }
    if (!opt) {
      opt = {};
    }

    opt = opt as ec.SignOptions;
    key = this.keyFromPrivate(key, enc);
    // @ts-ignore("BN can use readonly number[]")
    msg = new BN(msg, 'hex');
    const n = this.n!;
    const g = this.g! as curve.short.ShortPoint;
    const ns1 = n.sub(new BN(1));
    const drbg = new HMACDRBG();
    const d = key.getPrivate();
    for (let iter = 0; ; iter++) {
      const k =
        (opt as ec.SignOptions).k || new BN(drbg.randomBytes(n.byteLength()));

      if (k.cmpn(1) <= 0 || k.cmp(ns1) >= 0) {
        continue;
      }
      const Q = g.mul(k);
      const x = Q.getX();
      const r = msg.add(x).umod(n);
      if (r.cmpn(0) === 0 || r.add(k).cmp(n) === 0) {
        continue;
      }
      let s = d
        .addn(1)
        .invm(n)
        .mul(k.sub(r.mul(d).umod(n)))
        .umod(n);
      if (s.isZero()) {
        continue;
      }
      let recoveryParam =
        (Q.getY().isOdd() ? 1 : 0) | (Q.getX().cmp(r) !== 0 ? 2 : 0);
      if ((opt as ec.SignOptions).canonical && s.cmp(this.nh) > 0) {
        s = n.sub(s);
        recoveryParam ^= 1;
      }
      return new Signature({ r, s, recoveryParam });
    }
  }

  verify(
    msg: BNInput,
    signature: SignatureInput,
    key: Buffer | ec.KeyPair,
    enc?: string
  ): boolean {
    // @ts-ignore("BN can use readonly number[]")
    msg = new BN(msg, 'hex');
    const sig = new Signature(signature, 'hex');
    const P = this.keyFromPublic(key, enc).getPublic();
    const r = sig.r;
    const s = sig.s;
    const n = this.n!;
    const g = this.g as curve.short.ShortPoint;
    // 1 < r < n-1
    if (r.cmpn(1) < 0 || r.cmp(n) >= 0) {
      return false;
    }
    // 1 < s < n-1
    if (s.cmpn(1) < 0 || r.cmp(n) >= 0) {
      return false;
    }
    // t = (r + s)mod n
    const t = r.add(s).umod(n);
    if (t.cmpn(0) === 0) {
      return false;
    }

    // s*G + t*P
    const Q = g.mul(s).add(P.mul(t));
    const x = Q.getX();
    const R = msg.add(x).umod(n);
    return r.cmp(R) === 0;
  }
}
