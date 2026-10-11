import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SETS, SETS_ALL, randomInt, shuffle, generatePassword, generatePassphrase, passwordEntropy,
  passphraseEntropy, poolSize, rateEntropy, crackTimeText, sha1Hex, splitHash, countInRange,
} from '../src/generator.js';
import { WORDS } from '../src/wordlist.js';

// A fake random source that returns numbers from a list, for predictable tests.
const fakeSource = (values) => {
  let i = 0;
  return (count) => Uint32Array.from({ length: count }, () => values[i++ % values.length]);
};

test('randomInt stays in range', () => {
  for (let i = 0; i < 2000; i += 1) {
    const n = randomInt(7);
    assert.ok(n >= 0 && n < 7 && Number.isInteger(n));
  }
});

test('randomInt rejects values in the biased tail and redraws', () => {
  // For max 10, limit = floor(2^32/10)*10 = 4294967290. 4294967295 is in the tail, so it's skipped.
  const n = randomInt(10, fakeSource([4294967295, 42]));
  assert.equal(n, 2);
});

test('randomInt is roughly uniform', () => {
  const counts = new Array(6).fill(0);
  for (let i = 0; i < 60000; i += 1) counts[randomInt(6)] += 1;
  for (const c of counts) assert.ok(c > 9000 && c < 11000, `unexpected count ${c}`);
});

test('randomInt rejects bad ranges', () => {
  assert.throws(() => randomInt(0), /Invalid range/);
  assert.throws(() => randomInt(2.5), /Invalid range/);
});

test('shuffle keeps the same items', () => {
  const items = ['a', 'b', 'c', 'd', 'e'];
  assert.deepEqual([...shuffle(items)].sort(), items);
});

test('passwords have the right length and only use chosen characters', () => {
  const p = generatePassword({ length: 24, lower: true, numbers: true });
  assert.equal(p.length, 24);
  assert.match(p, /^[a-z0-9]+$/);
});

test('every chosen character type appears, every time', () => {
  for (let i = 0; i < 300; i += 1) {
    const p = generatePassword({ length: 8, upper: true, lower: true, numbers: true, symbols: true });
    assert.match(p, /[A-Z]/);
    assert.match(p, /[a-z]/);
    assert.match(p, /[0-9]/);
    assert.ok([...p].some((ch) => SETS.symbols.includes(ch)), `no symbol in ${p}`);
  }
});

test('avoid look-alikes removes 0, O, 1, l and I', () => {
  for (let i = 0; i < 200; i += 1) {
    const p = generatePassword({ length: 32, upper: true, lower: true, numbers: true, avoidLookalikes: true });
    assert.doesNotMatch(p, /[0O1lI]/);
  }
});

test('invalid password options are rejected', () => {
  assert.throws(() => generatePassword({ length: 16 }), /at least one type/);
  assert.throws(() => generatePassword({ length: 4, lower: true }), /between 8 and 128/);
  assert.throws(() => generatePassword({ length: 500, lower: true }), /between 8 and 128/);
});

test('the word list is the EFF large list: 7776 unique lowercase words', () => {
  assert.equal(WORDS.length, 7776);
  assert.equal(new Set(WORDS).size, 7776);
  assert.ok(WORDS.every((w) => /^[a-z-]+$/.test(w)));
});

test('passphrases have the requested words, separator and options', () => {
  const p = generatePassphrase({ words: 6, separator: '.' }, WORDS);
  assert.equal(p.split('.').length, 6);
  assert.ok(p.split('.').every((w) => WORDS.includes(w)));
  const q = generatePassphrase({ words: 4, separator: '-', capitalise: true, addNumber: true }, WORDS);
  const parts = q.split('-');
  assert.equal(parts.length, 5);
  assert.match(parts[0], /^[A-Z]/);
  assert.match(parts.at(-1), /^\d{1,2}$/);
});

test('passphrase word count is limited', () => {
  assert.throws(() => generatePassphrase({ words: 2 }, WORDS), /between 3 and 12/);
});

test('entropy maths', () => {
  assert.equal(passwordEntropy(16, 64), 96);
  assert.ok(Math.abs(passphraseEntropy(5, 7776) - 64.62) < 0.01);
  assert.equal(poolSize({ upper: true, lower: true, numbers: true, symbols: true }),
    SETS_ALL.upper.length + SETS_ALL.lower.length + SETS_ALL.numbers.length + SETS_ALL.symbols.length);
});

test('entropy ratings', () => {
  assert.equal(rateEntropy(40).label, 'Weak');
  assert.equal(rateEntropy(60).label, 'Fair');
  assert.equal(rateEntropy(80).label, 'Strong');
  assert.equal(rateEntropy(120).label, 'Excellent');
});

test('crack time text', () => {
  assert.equal(crackTimeText(10), 'less than a second');
  assert.match(crackTimeText(50), /hours|minutes/);
  assert.equal(crackTimeText(200), 'more than a trillion years');
});

test('sha1Hex matches a known value', async () => {
  // SHA-1("password") is a well-known test vector.
  assert.equal(await sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
});

test('only a 5-character prefix of the hash is sent', () => {
  const { prefix, suffix } = splitHash('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  assert.equal(prefix, '5BAA6');
  assert.equal(prefix.length, 5);
  assert.equal(suffix, '1E4C9B93F3F0682250B6CF8331B7EE68FD8');
});

test('countInRange finds our suffix in the API response', () => {
  const response = '0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:52256179\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:3';
  assert.equal(countInRange(response, '1E4C9B93F3F0682250B6CF8331B7EE68FD8'), 52256179);
  assert.equal(countInRange(response, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), 0);
});
