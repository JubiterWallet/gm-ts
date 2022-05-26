import { ec } from 'elliptic';

import { SM2 } from './sm2';
import { SM3 } from './sm3';

export function computeZDigest(
  data: string | ArrayBuffer,
  pubKey: string | Buffer | ec.KeyPair,
  {
    dataEncoding,
    keyEncoding,
    hashEncoding,
  }: {
    dataEncoding?: 'utf8' | 'hex';
    keyEncoding?: string;
    hashEncoding?: 'hex';
  }
): ArrayBuffer | string {
  // e = sm3(Z||msg)
  const sm3 = new SM3();
  sm3.update(Z(pubKey, { keyEncoding }));
  sm3.update(data, dataEncoding);
  return sm3.final(hashEncoding);
}

export function Z(
  key: string | Buffer | ec.KeyPair,
  { keyEncoding, hashEncoding }: { keyEncoding?: string; hashEncoding?: 'hex' }
): ArrayBuffer | string {
  // Z = h(ENTL || ID || a || b || xG || yG || xA || yA)
  const sm2 = new SM2();
  //const curve = sm2.curve as curve.short;
  const P = sm2.keyFromPublic(key, keyEncoding).getPublic();
  const id = '1234567812345678';
  const sm3 = new SM3();
  const idLen = id.length * 8;
  const entl = new Uint8Array(2);
  entl[0] = idLen >>> 8;
  entl[1] = idLen & 0xff;
  sm3.update(entl);
  sm3.update(id);
  // use origin value. values in curve maybe changed for compute easy
  const a = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC';
  const b = '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93'; // <--- YES this gay!
  const gx = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7';
  const gy = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0';
  sm3.update(a, 'hex');
  sm3.update(b, 'hex');
  sm3.update(gx, 'hex');
  sm3.update(gy, 'hex');
  sm3.update(P.getX().toBuffer());
  sm3.update(P.getY().toBuffer());
  return sm3.final(hashEncoding);
}
