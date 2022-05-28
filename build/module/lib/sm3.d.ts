/// <reference types="node" />
export declare class SM3 {
    readonly BLOCK_SIZE: 64;
    state: {
        A: number;
        B: number;
        C: number;
        D: number;
        E: number;
        F: number;
        G: number;
        H: number;
    };
    cache?: Buffer;
    total: Buffer;
    update(data: string | Buffer, encoding?: 'utf8' | 'hex'): void;
    final(encoding?: 'hex'): Buffer | string;
    private blockProcess;
}
