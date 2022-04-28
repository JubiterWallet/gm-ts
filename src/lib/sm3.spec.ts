import test from 'ava';

import { SM3 } from './sm3';

test('abc', (t) => {
  const sm3 = new SM3();
  sm3.update('abc');
  const r = sm3.final('hex');
  t.is(r, '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0');
});

test('abcd', (t) => {
  const sm3 = new SM3();
  sm3.update('abcd'.repeat(16));
  const r = sm3.final('hex');
  t.is(r, 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732');
});
