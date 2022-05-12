import BN from 'bn.js';
import { SignatureInput } from 'elliptic';
export declare class Signature {
    r: BN;
    s: BN;
    recoveryParam: number | null;
    constructor(sig: SignatureInput, enc?: 'hex');
    toDER(): number[];
    toDER(enc: 'hex'): string;
    private importDER;
}
