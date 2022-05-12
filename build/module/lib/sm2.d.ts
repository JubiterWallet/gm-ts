/// <reference types="node" />
import { BNInput, ec, SignatureInput } from 'elliptic';
export declare class SM2 extends ec {
    constructor();
    sign(msg: BNInput, key: Buffer | ec.KeyPair, enc: string, options?: ec.SignOptions): ec.Signature;
    sign(msg: BNInput, key: Buffer | ec.KeyPair, options?: ec.SignOptions): ec.Signature;
    verify(msg: BNInput, signature: SignatureInput, key: Buffer | ec.KeyPair, enc?: string): boolean;
}
