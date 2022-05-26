import { curve, ec } from 'elliptic';
import { SM2 } from './sm2';
import { SM3 } from './sm3';

export function computeZDigest(
  data: string | ArrayBuffer,
  pubKey: Buffer | ec.KeyPair,
  dataEnc?: 'utf8' | 'hex',
  keyEnc?: string,
  hashEnc?: 'hex'
): ArrayBuffer | string {
  // e = sm3(Z||msg)
  const sm3 = new SM3();
  sm3.update(Z(pubKey, keyEnc));
  sm3.update(data, dataEnc);
  return sm3.final(hashEnc);
}

export function Z(
  key: Buffer | ec.KeyPair,
  enc?: string
): ArrayBuffer | string {
  // Z = h(ENTL || ID || a || b || xG || yG || xA || yA)
  const sm2 = new SM2();
  const curve = sm2.curve as curve.short;
  const G = sm2.g as curve.base.BasePoint;
  const P = sm2.keyFromPublic(key, enc).getPublic();
  const id = Buffer.from('1234567812345678', 'hex');
  const sm3 = new SM3();
  const idLen = id.length * 8;
  const entl = new Uint8Array(2);
  new DataView(entl).setUint16(0, idLen);
  sm3.update(entl);
  sm3.update(id);
  sm3.update(curve.a as Uint8Array);
  sm3.update(curve.b as Uint8Array);
  sm3.update(G.getX().toBuffer());
  sm3.update(G.getY().toBuffer());
  sm3.update(P.getX().toBuffer());
  sm3.update(P.getY().toBuffer());
  return sm3.final();
}
