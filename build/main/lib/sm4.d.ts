/// <reference types="node" />
export declare class SM4 {
    readonly BLOCK_SIZE = 16;
    readonly SM4_KEY_SCHEDULE = 32;
    rk?: number[];
    constructor(key?: string | Buffer, encoding?: 'utf8' | 'hex');
    setKey(key: string | Buffer, encoding?: 'utf8' | 'hex'): void;
    encrypt(data: string | Buffer, encoding?: 'utf8' | 'hex', outEncoding?: 'utf8' | 'hex'): string | Buffer;
    decrypt(data: string | Buffer, encoding?: 'utf8' | 'hex', outEncoding?: string): string | Buffer;
}
