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
    cache?: Uint8Array;
    total: ArrayBuffer;
    update(data: string | ArrayBuffer, encoding?: 'utf8' | 'hex'): void;
    final(encoding?: 'hex'): ArrayBuffer | string;
    private blockProcess;
}
