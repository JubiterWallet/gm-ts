import test from 'ava';

import { SM4 } from './sm4';

test('0123456789ABCDEFFEDCBA9876543210', (t) => {
  const sm4 = new SM4();
  sm4.setKey('0123456789ABCDEFFEDCBA9876543210', 'hex');
  const enc = sm4.encrypt('0123456789ABCDEFFEDCBA9876543210', 'hex', 'hex');
  t.is(enc, '681edf34d206965e86b3e94f536e4246');
});

test('1 000 000 times', (t) => {
  const sm4 = new SM4();
  sm4.setKey('0123456789ABCDEFFEDCBA9876543210', 'hex');

  let enc = sm4.encrypt('0123456789ABCDEFFEDCBA9876543210', 'hex', 'hex');
  for (let i = 0; i < 999999; i++) {
    enc = sm4.encrypt(enc, 'hex', 'hex');
  }
  t.is(enc, '595298c7c6fd271f0402f804c33d3f66');
});
