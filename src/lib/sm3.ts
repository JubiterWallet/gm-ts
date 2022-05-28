export class SM3 {
  readonly BLOCK_SIZE = 64 as const;
  // IV
  state = {
    A: 0x7380166f,
    B: 0x4914b2b9,
    C: 0x172442d7,
    D: 0xda8a0600,
    E: 0xa96f30bc,
    F: 0x163138aa,
    G: 0xe38dee4d,
    H: 0xb0fb0e4e,
  };

  // max 64 bytes, cleared when final
  cache?: Buffer = undefined;
  // big-ending byte length
  total = Buffer.alloc(8);

  update(data: string | Buffer, encoding?: 'utf8' | 'hex') {
    if (data.length === 0) {
      return;
    }
    if (typeof data === 'string') {
      data = Buffer.from(data, encoding);
    }
    const len = data.length;
    let n = 0;
    // update total
    let h = this.total.readUint32BE(0);
    let l = this.total.readUint32BE(4);
    l += len;
    l = l >>> 0;
    if (l < len) {
      h += 1;
    }
    this.total.writeUint32BE(U32(h), 0);
    this.total.writeUint32BE(U32(l), 4);
    if (this.cache) {
      n = this.cache.length;
      if (len >= this.BLOCK_SIZE || len + n >= this.BLOCK_SIZE) {
        // make a block
        const block = Buffer.alloc(this.BLOCK_SIZE);
        block.set(this.cache);
        block.set(data.subarray(0, this.BLOCK_SIZE - n), n);
        this.blockProcess(block);

        data = data.subarray(this.BLOCK_SIZE - n);
        // have process
        this.cache = undefined;
      } else {
        // not fill a block, cache it
        const cache = Buffer.alloc(len + n);
        cache.set(this.cache);
        cache.set(data, n);
        this.cache = cache;
        return;
      }
    }

    for (
      ;
      data.length >= this.BLOCK_SIZE;
      data = data.subarray(this.BLOCK_SIZE)
    ) {
      this.blockProcess(data.subarray(0, this.BLOCK_SIZE));
    }

    if (data.length > 0) {
      // cache remained
      this.cache = Buffer.from(data);
    }
  }

  final(encoding?: 'hex'): Buffer | string {
    const block = Buffer.alloc(this.BLOCK_SIZE);
    let n = 0;
    if (this.cache) {
      block.set(this.cache);
      n = this.cache.length;
      this.cache = undefined;
    }
    block[n] = 0x80;
    n += 1;
    if (n > this.BLOCK_SIZE - 8) {
      this.blockProcess(block);
      n = 0;
      block.fill(0);
    }

    // bit length
    let h = this.total.readUint32BE(0);
    let l = this.total.readUint32BE(4);
    this.total.fill(0);

    h = (h << 3) | (l >>> 29);
    l = l << 3;
    block.writeUint32BE(U32(h), this.BLOCK_SIZE - 8);
    block.writeUint32BE(U32(l), this.BLOCK_SIZE - 4);
    this.blockProcess(block);

    const d = Buffer.alloc(32);
    const { A, B, C, D, E, F, G, H } = this.state;
    d.writeUint32BE(U32(A), 0);
    d.writeUint32BE(U32(B), 4);
    d.writeUint32BE(U32(C) >>> 0, 8);
    d.writeUint32BE(U32(D), 12);
    d.writeUint32BE(U32(E), 16);
    d.writeUint32BE(U32(F), 20);
    d.writeUint32BE(U32(G), 24);
    d.writeUint32BE(U32(H), 28);
    return encoding ? d.toString(encoding) : d;
  }

  private blockProcess(block: Buffer) {
    let A, B, C, D, E, F, G, H;
    ({ A, B, C, D, E, F, G, H } = this.state);
    let W00 = block.readUint32BE(0);
    let W01 = block.readUint32BE(4);
    let W02 = block.readUint32BE(8);
    let W03 = block.readUint32BE(12);
    let W04 = block.readUint32BE(16);
    let W05 = block.readUint32BE(20);
    let W06 = block.readUint32BE(24);
    let W07 = block.readUint32BE(28);
    let W08 = block.readUint32BE(32);
    let W09 = block.readUint32BE(36);
    let W10 = block.readUint32BE(40);
    let W11 = block.readUint32BE(44);
    let W12 = block.readUint32BE(48);
    let W13 = block.readUint32BE(52);
    let W14 = block.readUint32BE(56);
    let W15 = block.readUint32BE(60);
    [B, D, F, H] = R1(A, B, C, D, E, F, G, H, 0x79cc4519, W00, W00 ^ W04);
    W00 = EXPAND(W00, W07, W13, W03, W10);
    [A, C, E, G] = R1(D, A, B, C, H, E, F, G, 0xf3988a32, W01, W01 ^ W05);
    W01 = EXPAND(W01, W08, W14, W04, W11);
    [D, B, H, F] = R1(C, D, A, B, G, H, E, F, 0xe7311465, W02, W02 ^ W06);
    W02 = EXPAND(W02, W09, W15, W05, W12);
    [C, A, G, E] = R1(B, C, D, A, F, G, H, E, 0xce6228cb, W03, W03 ^ W07);
    W03 = EXPAND(W03, W10, W00, W06, W13);
    [B, D, F, H] = R1(A, B, C, D, E, F, G, H, 0x9cc45197, W04, W04 ^ W08);
    W04 = EXPAND(W04, W11, W01, W07, W14);
    [A, C, E, G] = R1(D, A, B, C, H, E, F, G, 0x3988a32f, W05, W05 ^ W09);
    W05 = EXPAND(W05, W12, W02, W08, W15);
    [D, B, H, F] = R1(C, D, A, B, G, H, E, F, 0x7311465e, W06, W06 ^ W10);
    W06 = EXPAND(W06, W13, W03, W09, W00);
    [C, A, G, E] = R1(B, C, D, A, F, G, H, E, 0xe6228cbc, W07, W07 ^ W11);
    W07 = EXPAND(W07, W14, W04, W10, W01);
    [B, D, F, H] = R1(A, B, C, D, E, F, G, H, 0xcc451979, W08, W08 ^ W12);
    W08 = EXPAND(W08, W15, W05, W11, W02);
    [A, C, E, G] = R1(D, A, B, C, H, E, F, G, 0x988a32f3, W09, W09 ^ W13);
    W09 = EXPAND(W09, W00, W06, W12, W03);
    [D, B, H, F] = R1(C, D, A, B, G, H, E, F, 0x311465e7, W10, W10 ^ W14);
    W10 = EXPAND(W10, W01, W07, W13, W04);
    [C, A, G, E] = R1(B, C, D, A, F, G, H, E, 0x6228cbce, W11, W11 ^ W15);
    W11 = EXPAND(W11, W02, W08, W14, W05);
    [B, D, F, H] = R1(A, B, C, D, E, F, G, H, 0xc451979c, W12, W12 ^ W00);
    W12 = EXPAND(W12, W03, W09, W15, W06);
    [A, C, E, G] = R1(D, A, B, C, H, E, F, G, 0x88a32f39, W13, W13 ^ W01);
    W13 = EXPAND(W13, W04, W10, W00, W07);
    [D, B, H, F] = R1(C, D, A, B, G, H, E, F, 0x11465e73, W14, W14 ^ W02);
    W14 = EXPAND(W14, W05, W11, W01, W08);
    [C, A, G, E] = R1(B, C, D, A, F, G, H, E, 0x228cbce6, W15, W15 ^ W03);
    W15 = EXPAND(W15, W06, W12, W02, W09);
    [B, D, F, H] = R2(A, B, C, D, E, F, G, H, 0x9d8a7a87, W00, W00 ^ W04);
    W00 = EXPAND(W00, W07, W13, W03, W10);
    [A, C, E, G] = R2(D, A, B, C, H, E, F, G, 0x3b14f50f, W01, W01 ^ W05);
    W01 = EXPAND(W01, W08, W14, W04, W11);
    [D, B, H, F] = R2(C, D, A, B, G, H, E, F, 0x7629ea1e, W02, W02 ^ W06);
    W02 = EXPAND(W02, W09, W15, W05, W12);
    [C, A, G, E] = R2(B, C, D, A, F, G, H, E, 0xec53d43c, W03, W03 ^ W07);
    W03 = EXPAND(W03, W10, W00, W06, W13);
    [B, D, F, H] = R2(A, B, C, D, E, F, G, H, 0xd8a7a879, W04, W04 ^ W08);
    W04 = EXPAND(W04, W11, W01, W07, W14);
    [A, C, E, G] = R2(D, A, B, C, H, E, F, G, 0xb14f50f3, W05, W05 ^ W09);
    W05 = EXPAND(W05, W12, W02, W08, W15);
    [D, B, H, F] = R2(C, D, A, B, G, H, E, F, 0x629ea1e7, W06, W06 ^ W10);
    W06 = EXPAND(W06, W13, W03, W09, W00);
    [C, A, G, E] = R2(B, C, D, A, F, G, H, E, 0xc53d43ce, W07, W07 ^ W11);
    W07 = EXPAND(W07, W14, W04, W10, W01);
    [B, D, F, H] = R2(A, B, C, D, E, F, G, H, 0x8a7a879d, W08, W08 ^ W12);
    W08 = EXPAND(W08, W15, W05, W11, W02);
    [A, C, E, G] = R2(D, A, B, C, H, E, F, G, 0x14f50f3b, W09, W09 ^ W13);
    W09 = EXPAND(W09, W00, W06, W12, W03);
    [D, B, H, F] = R2(C, D, A, B, G, H, E, F, 0x29ea1e76, W10, W10 ^ W14);
    W10 = EXPAND(W10, W01, W07, W13, W04);
    [C, A, G, E] = R2(B, C, D, A, F, G, H, E, 0x53d43cec, W11, W11 ^ W15);
    W11 = EXPAND(W11, W02, W08, W14, W05);
    [B, D, F, H] = R2(A, B, C, D, E, F, G, H, 0xa7a879d8, W12, W12 ^ W00);
    W12 = EXPAND(W12, W03, W09, W15, W06);
    [A, C, E, G] = R2(D, A, B, C, H, E, F, G, 0x4f50f3b1, W13, W13 ^ W01);
    W13 = EXPAND(W13, W04, W10, W00, W07);
    [D, B, H, F] = R2(C, D, A, B, G, H, E, F, 0x9ea1e762, W14, W14 ^ W02);
    W14 = EXPAND(W14, W05, W11, W01, W08);
    [C, A, G, E] = R2(B, C, D, A, F, G, H, E, 0x3d43cec5, W15, W15 ^ W03);
    W15 = EXPAND(W15, W06, W12, W02, W09);
    [B, D, F, H] = R2(A, B, C, D, E, F, G, H, 0x7a879d8a, W00, W00 ^ W04);
    W00 = EXPAND(W00, W07, W13, W03, W10);
    [A, C, E, G] = R2(D, A, B, C, H, E, F, G, 0xf50f3b14, W01, W01 ^ W05);
    W01 = EXPAND(W01, W08, W14, W04, W11);
    [D, B, H, F] = R2(C, D, A, B, G, H, E, F, 0xea1e7629, W02, W02 ^ W06);
    W02 = EXPAND(W02, W09, W15, W05, W12);
    [C, A, G, E] = R2(B, C, D, A, F, G, H, E, 0xd43cec53, W03, W03 ^ W07);
    W03 = EXPAND(W03, W10, W00, W06, W13);
    [B, D, F, H] = R2(A, B, C, D, E, F, G, H, 0xa879d8a7, W04, W04 ^ W08);
    W04 = EXPAND(W04, W11, W01, W07, W14);
    [A, C, E, G] = R2(D, A, B, C, H, E, F, G, 0x50f3b14f, W05, W05 ^ W09);
    W05 = EXPAND(W05, W12, W02, W08, W15);
    [D, B, H, F] = R2(C, D, A, B, G, H, E, F, 0xa1e7629e, W06, W06 ^ W10);
    W06 = EXPAND(W06, W13, W03, W09, W00);
    [C, A, G, E] = R2(B, C, D, A, F, G, H, E, 0x43cec53d, W07, W07 ^ W11);
    W07 = EXPAND(W07, W14, W04, W10, W01);
    [B, D, F, H] = R2(A, B, C, D, E, F, G, H, 0x879d8a7a, W08, W08 ^ W12);
    W08 = EXPAND(W08, W15, W05, W11, W02);
    [A, C, E, G] = R2(D, A, B, C, H, E, F, G, 0x0f3b14f5, W09, W09 ^ W13);
    W09 = EXPAND(W09, W00, W06, W12, W03);
    [D, B, H, F] = R2(C, D, A, B, G, H, E, F, 0x1e7629ea, W10, W10 ^ W14);
    W10 = EXPAND(W10, W01, W07, W13, W04);
    [C, A, G, E] = R2(B, C, D, A, F, G, H, E, 0x3cec53d4, W11, W11 ^ W15);
    W11 = EXPAND(W11, W02, W08, W14, W05);
    [B, D, F, H] = R2(A, B, C, D, E, F, G, H, 0x79d8a7a8, W12, W12 ^ W00);
    W12 = EXPAND(W12, W03, W09, W15, W06);
    [A, C, E, G] = R2(D, A, B, C, H, E, F, G, 0xf3b14f50, W13, W13 ^ W01);
    W13 = EXPAND(W13, W04, W10, W00, W07);
    [D, B, H, F] = R2(C, D, A, B, G, H, E, F, 0xe7629ea1, W14, W14 ^ W02);
    W14 = EXPAND(W14, W05, W11, W01, W08);
    [C, A, G, E] = R2(B, C, D, A, F, G, H, E, 0xcec53d43, W15, W15 ^ W03);
    W15 = EXPAND(W15, W06, W12, W02, W09);
    [B, D, F, H] = R2(A, B, C, D, E, F, G, H, 0x9d8a7a87, W00, W00 ^ W04);
    W00 = EXPAND(W00, W07, W13, W03, W10);
    [A, C, E, G] = R2(D, A, B, C, H, E, F, G, 0x3b14f50f, W01, W01 ^ W05);
    W01 = EXPAND(W01, W08, W14, W04, W11);
    [D, B, H, F] = R2(C, D, A, B, G, H, E, F, 0x7629ea1e, W02, W02 ^ W06);
    W02 = EXPAND(W02, W09, W15, W05, W12);
    [C, A, G, E] = R2(B, C, D, A, F, G, H, E, 0xec53d43c, W03, W03 ^ W07);
    W03 = EXPAND(W03, W10, W00, W06, W13);
    [B, D, F, H] = R2(A, B, C, D, E, F, G, H, 0xd8a7a879, W04, W04 ^ W08);
    [A, C, E, G] = R2(D, A, B, C, H, E, F, G, 0xb14f50f3, W05, W05 ^ W09);
    [D, B, H, F] = R2(C, D, A, B, G, H, E, F, 0x629ea1e7, W06, W06 ^ W10);
    [C, A, G, E] = R2(B, C, D, A, F, G, H, E, 0xc53d43ce, W07, W07 ^ W11);
    [B, D, F, H] = R2(A, B, C, D, E, F, G, H, 0x8a7a879d, W08, W08 ^ W12);
    [A, C, E, G] = R2(D, A, B, C, H, E, F, G, 0x14f50f3b, W09, W09 ^ W13);
    [D, B, H, F] = R2(C, D, A, B, G, H, E, F, 0x29ea1e76, W10, W10 ^ W14);
    [C, A, G, E] = R2(B, C, D, A, F, G, H, E, 0x53d43cec, W11, W11 ^ W15);
    [B, D, F, H] = R2(A, B, C, D, E, F, G, H, 0xa7a879d8, W12, W12 ^ W00);
    [A, C, E, G] = R2(D, A, B, C, H, E, F, G, 0x4f50f3b1, W13, W13 ^ W01);
    [D, B, H, F] = R2(C, D, A, B, G, H, E, F, 0x9ea1e762, W14, W14 ^ W02);
    [C, A, G, E] = R2(B, C, D, A, F, G, H, E, 0x3d43cec5, W15, W15 ^ W03);

    this.state.A ^= A;
    this.state.B ^= B;
    this.state.C ^= C;
    this.state.D ^= D;
    this.state.E ^= E;
    this.state.F ^= F;
    this.state.G ^= G;
    this.state.H ^= H;
  }
}

type State = {
  readonly A: number;
  readonly B: number;
  readonly C: number;
  readonly D: number;
  readonly E: number;
  readonly F: number;
  readonly G: number;
  readonly H: number;
};

// function logState(...states: number[]) {
//   const ss = states.map((x) => x.toString(16).padStart(8, '0'));
//   console.log(ss.join(' '));
// }

function U32(a: number): number {
  return a >>> 0;
}

function ROTATE(a: number, n: number): number {
  return (a << n) | (a >>> (32 - n));
}

function P0(x: number): number {
  return x ^ ROTATE(x, 9) ^ ROTATE(x, 17);
}

function P1(x: number): number {
  return x ^ ROTATE(x, 15) ^ ROTATE(x, 23);
}

type FF = (x: number, y: number, z: number) => number;
type GG = (x: number, y: number, z: number) => number;

function FF0(x: number, y: number, z: number): number {
  return x ^ y ^ z;
}

function GG0(x: number, y: number, z: number): number {
  return x ^ y ^ z;
}

function FF1(x: number, y: number, z: number): number {
  // return (x & y) ^ (x & z) ^ (y & z);
  return (x & y) | ((x | y) & z);
}

function GG1(x: number, y: number, z: number): number {
  // return (x & y) | (~x & z);
  return z ^ (x & (y ^ z));
}

function EXPAND(
  W0: number,
  W7: number,
  W13: number,
  W3: number,
  W10: number
): number {
  return P1(W0 ^ W7 ^ ROTATE(W13, 15)) ^ ROTATE(W3, 7) ^ W10;
}

type RNDResult = readonly [number, number, number, number];
function RND(
  state: State,
  TJ: number,
  Wi: number,
  Wj: number,
  FF: FF,
  GG: GG
): RNDResult {
  // eslint-disable-next-line prefer-const
  let { A, B, C, D, E, F, G, H } = state;
  const A12 = ROTATE(A, 12);
  const A12_SM = A12 + E + TJ;
  const SS1 = ROTATE(A12_SM, 7);
  const TT1 = FF(A, B, C) + D + (SS1 ^ A12) + Wj;
  const TT2 = GG(E, F, G) + H + SS1 + Wi;
  B = ROTATE(B, 9);
  D = TT1;
  F = ROTATE(F, 19);
  H = P0(TT2);
  return [B, D, F, H];
}

function R1(
  A: number,
  B: number,
  C: number,
  D: number,
  E: number,
  F: number,
  G: number,
  H: number,
  TJ: number,
  Wi: number,
  Wj: number
): RNDResult {
  return RND({ A, B, C, D, E, F, G, H }, TJ, Wi, Wj, FF0, GG0);
}

function R2(
  A: number,
  B: number,
  C: number,
  D: number,
  E: number,
  F: number,
  G: number,
  H: number,
  TJ: number,
  Wi: number,
  Wj: number
): RNDResult {
  return RND({ A, B, C, D, E, F, G, H }, TJ, Wi, Wj, FF1, GG1);
}
