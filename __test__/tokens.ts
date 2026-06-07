/* eslint-disable import/no-extraneous-dependencies */

import assert from 'node:assert';

import {
  beforeAll,
  describe,
  expect,
  it,
} from '@jest/globals';

import Tokens, { verify } from '../src/tokens';

let secret: string;
let tokens: Tokens;

/**
 * Returns "true" if the given string is URL-safe; returns "false" otherwise.
 */
function isUrlSafe(s: string): boolean {
  return s === encodeURIComponent(s);
}

describe('Tokens', () => {
  describe('options', () => {
    describe('saltLength', () => {
      it('should reject non-numbers', () => {
        assert.throws(
          () => {
            // @ts-expect-error "for test purposes"
            new Tokens({ saltLength: 'bogus' }); // eslint-disable-line no-new
          },
          /option saltLength/,
        );
      });

      it('should reject NaN', () => {
        assert.throws(
          () => {
            // eslint-disable-next-line no-new
            new Tokens({ saltLength: NaN });
          },
          /option saltLength/,
        );
      });

      it('should reject Infinity', () => {
        assert.throws(
          () => {
            // eslint-disable-next-line no-new
            new Tokens({ saltLength: Infinity });
          },
          /option saltLength/,
        );
      });
    });

    describe('secretLength', () => {
      it('should reject non-numbers', () => {
        assert.throws(
          () => {
            // @ts-expect-error "for test purposes"
            new Tokens({ secretLength: 'bogus' }); // eslint-disable-line no-new
          },
          /option secretLength/,
        );
      });

      it('should reject NaN', () => {
        assert.throws(
          () => {
            // eslint-disable-next-line no-new
            new Tokens({ secretLength: NaN });
          },
          /option secretLength/,
        );
      });

      it('should reject Infinity', () => {
        assert.throws(
          () => {
            // eslint-disable-next-line no-new
            new Tokens({ secretLength: Infinity });
          },
          /option secretLength/,
        );
      });

      it('should generate secret with specified byte length', () => {
        // 3 bytes = 4 base-64 characters
        // 4 bytes = 6 base-64 characters
        assert.strictEqual(
          new Tokens({ secretLength: 3 }).secret().length,
          4,
        );
        assert.strictEqual(
          new Tokens({ secretLength: 4 }).secret().length,
          6,
        );
      });
    });
  });

  describe('.create(secret)', () => {
    beforeAll(() => {
      tokens = new Tokens();
      secret = tokens.secret();
    });

    it('should require secret', () => {
      assert.throws(() => {
        // @ts-expect-error "for test purposes"
        tokens.create();
      }, /argument secret.*required/);
    });

    it('should reject non-string secret', () => {
      assert.throws(() => {
        // @ts-expect-error "for test purposes"
        tokens.create(42);
      }, /argument secret.*required/);
    });

    it('should reject empty string secret', () => {
      assert.throws(() => {
        tokens.create('');
      }, /argument secret.*required/);
    });

    it('should create a token', () => {
      const token = tokens.create(secret);
      assert.ok(typeof token === 'string');
    });

    it('should always be the same length', () => {
      const token = tokens.create(secret);
      assert.ok(token.length > 0);

      for (let i = 0; i < 1000; i++) {
        assert.strictEqual(
          tokens.create(secret).length,
          token.length,
        );
      }
    });

    it('should not contain /, +, or =', () => {
      for (let i = 0; i < 1000; i++) {
        const token = tokens.create(secret);
        assert(isUrlSafe(token));
      }
    });
  });

  describe('.secret()', () => {
    beforeAll(() => {
      tokens = new Tokens();
    });

    it('should create a secret', () => {
      const localSecret = tokens.secret();
      assert.ok(typeof localSecret === 'string');
      assert.ok(localSecret.length > 0);
    });
  });

  describe('.verify(secret, token)', () => {
    beforeAll(() => {
      tokens = new Tokens();
      secret = tokens.secret();
    });

    it('should return `true` with valid tokens', () => {
      const token = tokens.create(secret);
      assert.ok(verify(secret, token));
    });

    it('should return `false` with invalid tokens', () => {
      const token = tokens.create(secret);
      assert.ok(!verify(tokens.secret(), token));
      assert.ok(!verify('asdfasdfasdf', token));
    });

    it('should return `false` with invalid secret', () => {
      // @ts-expect-error "for test purposes"
      assert.ok(!verify());
      // @ts-expect-error "for test purposes"
      assert.ok(!verify([]));
    });

    it('should return `false` with invalid tokens (2)', () => {
      // @ts-expect-error "for test purposes"
      assert(!verify(secret, undefined));
      // @ts-expect-error "for test purposes"
      assert(!verify(secret, []));
      assert(!verify(secret, 'hi'));
    });
  });
});

/**
 * Returns a character with the code equal to that of `char` plus `n`.
 */
function bumpCharCode(char: string, n: number): string {
  return String.fromCharCode(char.charCodeAt(0) + n);
}

/**
 * Generates (a non-crypto-secure) random character, from the Base64 URL set,
 * different from the given character `c` and "-".
 */
function randomCharOtherThan(c: string): string {
  let res: string;

  // See: https://en.wikipedia.org/wiki/Base64#Alphabet
  const idx = Math.floor(64 * Math.random());
  if (idx < 26) res = bumpCharCode('A', idx);
  else if (idx < 52) res = bumpCharCode('a', idx - 26);
  else if (idx < 62) res = bumpCharCode('0', idx - 52);
  else res = '_'; // "_" for both `idx` 62 and 63, to avoid "-".

  return res === c ? randomCharOtherThan(c) : res;
}

/**
 * Returns a copy of `s` with the character at index `idx` replaced by
 * the given `char`.
 */
function replaceCharAt(s: string, idx: number, char: string): string {
  return `${s.slice(0, idx)}${char}${s.slice(idx + 1)}`;
}

/**
 * Returns a copy of `s` with the character at index `idx` replaced by
 * a different, random character, different from "-".
 */
function mutated(s: string, idx: number): string {
  const char = randomCharOtherThan(s.slice(idx, idx + 1));
  return replaceCharAt(s, idx, char);
}

/**
 * Generate (a non-crypto-secure) random string of the given `length`,
 * with characters from the Base64 URL set, different from "-".
 */
function randomString(length: number): string {
  let res = '';
  for (let i = 0; i < length; ++i) {
    res += randomCharOtherThan('-');
  }
  return res;
}

it('must pass extensive test', () => {
  tokens = new Tokens();
  secret = tokens.secret();

  // The number of trials. As we are testing with randomly generated tokens,
  // repeating the test loop N times verifies that the chance that something
  // does not work correctly is less or about 1 in N. The current value 10 000
  // means the chance of error at, or below 0.01%.
  const N = 10000;

  // NOTE: It is tempting to also time successful and failed verifications here,
  // to test resilence to the timing attacks; however, I believe, with just
  // 10 000 iterations, and these, non-specifically designed, mutations of
  // the valid token it is not possible. To test that, one should code a real
  // timing attack logic, which works for a non-timing-safe token validation,
  // and then verify that it fails with the actual validation algorithm.
  for (let i = 0; i < N; ++i) {
    const token = tokens.create(secret);

    expect(isUrlSafe(token)).toBe(true);

    // Verification of a valid token.
    expect(verify(secret, token)).toBe(true);

    const dashIdx = token.indexOf('-');

    // Verification of bad tokens, different from the valid one by a single
    // character at selected positions.
    expect(verify(secret, mutated(token, 0))).toBe(false);
    expect(verify(secret, mutated(token, dashIdx + 1))).toBe(false);
    expect(verify(secret, mutated(token, token.length - 1))).toBe(false);

    // Verification of a random, wrong token.
    const badToken = replaceCharAt(randomString(token.length), dashIdx, '-');
    expect(verify(secret, badToken)).toBe(false);
  }
});
