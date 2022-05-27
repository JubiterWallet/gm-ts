/// <reference types="node" />
import { ec } from 'elliptic';
export declare function computeZDigest(data: string | ArrayBuffer, pubKey: string | Buffer | ec.KeyPair, { dataEncoding, keyEncoding, hashEncoding, }: {
    dataEncoding?: 'utf8' | 'hex';
    keyEncoding?: string;
    hashEncoding?: 'hex';
}): ArrayBuffer | string;
export declare function Z(key: string | Buffer | ec.KeyPair, { keyEncoding, hashEncoding }: {
    keyEncoding?: string;
    hashEncoding?: 'hex';
}): ArrayBuffer | string;
