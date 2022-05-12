export declare class SM4 {
    readonly BLOCK_SIZE = 16;
    readonly SM4_KEY_SCHEDULE = 32;
    rk?: number[];
    constructor(key?: string | ArrayBuffer, encoding?: 'utf8' | 'hex');
    setKey(key: string | ArrayBuffer, encoding?: 'utf8' | 'hex'): void;
    encrypt(data: string | ArrayBuffer, encoding?: 'utf8' | 'hex', outEncoding?: 'utf8' | 'hex'): string | ArrayBuffer;
    decrypt(data: string | ArrayBuffer, encoding?: 'utf8' | 'hex', outEncoding?: string): string | ArrayBuffer;
}
