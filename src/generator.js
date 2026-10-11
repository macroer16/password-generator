// Password and passphrase generation, strength maths and breach-check helpers.
// No DOM code here, so it all runs (and is tested) in Node too.
//
// Randomness comes from the Web Crypto API (crypto.getRandomValues), which is designed
// for security. The old version used Math.random(), which is NOT safe for passwords.

export const SETS = Object.freeze({
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',      // no I or O (look like 1 and 0)
  lower: 'abcdefghijkmnopqrstuvwxyz',     // no l (looks like 1 and I)
  numbers: '23456789',                    // no 0 or 1
  symbols: '!@#$%^&*()-_=+[]{};:,.?',
});
export const SETS_ALL = Object.freeze({
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: SETS.symbols,
});

/** The default random source: secure random 32-bit numbers. Tests can pass a fake one. */
export function cryptoRandomSource(count) {
  return crypto.getRandomValues(new Uint32Array(count));
}

/**
 * A random whole number from 0 to max-1 with NO bias.
 * Simply using (random % max) favours small numbers slightly, so values in the
 * uneven "tail" are thrown away and redrawn (rejection sampling).
 */
export function randomInt(max, source = cryptoRandomSource) {
  if (!Number.isInteger(max) || max < 1 || max > 2 ** 32) throw new Error(`Invalid range: ${max}`);
  const limit = Math.floor(2 ** 32 / max) * max;
  for (;;) {
    const [n] = source(1);
    if (n < limit) return n % max;
  }
}

/** Shuffle a copy of an array fairly (Fisher-Yates). */
export function shuffle(items, source = cryptoRandomSource) {
  const a = [...items];
  for (let i = a.length - 1; i > 0; i -= 1) {
    const j = randomInt(i + 1, source);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/**
 * Generate a password.
 * @param {{length:number, upper?:boolean, lower?:boolean, numbers?:boolean, symbols?:boolean, avoidLookalikes?:boolean}} opts
 * Guarantees at least one character from every chosen set.
 */
export function generatePassword(opts, source = cryptoRandomSource) {
  const sets = opts.avoidLookalikes ? SETS : SETS_ALL;
  const chosen = ['upper', 'lower', 'numbers', 'symbols'].filter((k) => opts[k]).map((k) => sets[k]);
  if (chosen.length === 0) throw new Error('Choose at least one type of character');
  const length = opts.length;
  if (!Number.isInteger(length) || length < 8 || length > 128) throw new Error('Length must be between 8 and 128');
  if (length < chosen.length) throw new Error('Password is too short for the chosen character types');

  const pool = chosen.join('');
  // One from each chosen set, the rest from the whole pool, then shuffle so the
  // guaranteed characters aren't always at the start.
  const chars = chosen.map((set) => set[randomInt(set.length, source)]);
  while (chars.length < length) chars.push(pool[randomInt(pool.length, source)]);
  return shuffle(chars, source).join('');
}

/** Generate a passphrase from a word list, e.g. "orbit-velvet-candle-sprout-ladder". */
export function generatePassphrase({ words = 5, separator = '-', capitalise = false, addNumber = false }, wordlist, source = cryptoRandomSource) {
  if (!Number.isInteger(words) || words < 3 || words > 12) throw new Error('Choose between 3 and 12 words');
  const picked = Array.from({ length: words }, () => {
    const w = wordlist[randomInt(wordlist.length, source)];
    return capitalise ? w[0].toUpperCase() + w.slice(1) : w;
  });
  if (addNumber) picked.push(String(randomInt(100, source)));
  return picked.join(separator);
}

/**
 * Entropy in bits: how many guesses an attacker who knows HOW it was generated would need.
 * Each character picked from a pool of N adds log2(N) bits; each word from W words adds log2(W).
 */
export function passwordEntropy(length, poolSize) {
  return length * Math.log2(poolSize);
}
export function passphraseEntropy(words, wordlistSize, addNumber = false) {
  return words * Math.log2(wordlistSize) + (addNumber ? Math.log2(100) : 0);
}
export function poolSize(opts) {
  const sets = opts.avoidLookalikes ? SETS : SETS_ALL;
  return ['upper', 'lower', 'numbers', 'symbols'].filter((k) => opts[k]).reduce((n, k) => n + sets[k].length, 0);
}

/** Plain-English rating for a number of bits. */
export function rateEntropy(bits) {
  if (bits >= 100) return { label: 'Excellent', note: 'Far beyond what anyone could guess, even with huge computing power.' };
  if (bits >= 75) return { label: 'Strong', note: 'Safe for important accounts like email and banking.' };
  if (bits >= 55) return { label: 'Fair', note: 'OK for low-value accounts. Make it longer for anything important.' };
  return { label: 'Weak', note: 'Could be cracked with enough computing power. Make it longer.' };
}

/**
 * Rough time to guess at a given rate (on average, half the possibilities).
 * Default rate: 10 billion guesses a second, an offline attack on a fast password hash.
 */
export function crackTimeText(bits, guessesPerSecond = 1e10) {
  const seconds = 2 ** (bits - 1) / guessesPerSecond;
  const units = [
    ['years', 365.25 * 24 * 3600], ['days', 24 * 3600], ['hours', 3600], ['minutes', 60], ['seconds', 1],
  ];
  if (seconds < 1) return 'less than a second';
  const year = units[0][1];
  if (seconds > year * 1e12) return 'more than a trillion years';
  for (const [name, size] of units) {
    if (seconds >= size) {
      const value = seconds / size;
      const rounded = value >= 100 ? Math.round(value).toLocaleString('en-GB') : value.toFixed(value < 10 ? 1 : 0);
      return `about ${rounded} ${name}`;
    }
  }
  return 'less than a second';
}

/** SHA-1 of a string as uppercase hex (used only for the k-anonymity breach check). */
export async function sha1Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-1', bytes);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/**
 * Have I Been Pwned "range" API: only the first 5 characters of the hash are sent.
 * The service returns every hash suffix starting with that prefix, with a count,
 * and we look for ours locally. The password itself never leaves the browser.
 */
export function splitHash(hashHex) {
  return { prefix: hashHex.slice(0, 5), suffix: hashHex.slice(5) };
}

/** Find how many times a suffix appears in the range API's response text. */
export function countInRange(responseText, suffix) {
  for (const line of responseText.split('\n')) {
    const [s, count] = line.trim().split(':');
    if (s && s.toUpperCase() === suffix.toUpperCase()) return Number.parseInt(count, 10) || 0;
  }
  return 0;
}

export const RANGE_URL = 'https://api.pwnedpasswords.com/range/';
