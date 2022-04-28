import test from 'ava';

import { SM2 } from './sm2';

test('gen keypair', (t) => {
  const sm2 = new SM2();
  const key = sm2.genKeyPair();
  t.assert(key.validate());
  t.log('d: ', key.getPrivate('hex'));
  t.log('P: ', key.getPublic('hex'));
});

test('sign/verify', (t) => {
  const sm2 = new SM2();
  const msg = Buffer.from("B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76", 'hex');
  const key = sm2.genKeyPair();
  const sig = key.sign(msg, 'hex');
  t.log('d: ', key.getPrivate('hex'));
  t.log('P: ', key.getPublic('hex'));
  t.log('msg: ', msg.toString('hex'));
  t.log('sig: ', sig.toDER('hex'));
  t.assert(key.verify(msg, sig));
})
