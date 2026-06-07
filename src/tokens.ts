import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Hash a string with SHA256, returning url-safe base64.
 */
function hash(str: string): string {
  return createHash('sha256').update(str, 'ascii').digest('base64url');
}

/**
 * Tokenize a secret and salt.
 */
function privateTokenize(secret: string, salt: string): string {
  return `${salt}-${hash(`${salt}-${secret}`)}`;
}

/**
 * Verify if a given token is valid for a given secret.
 */
export function verify(secret: string, token: string): boolean {
  if (!secret || typeof secret !== 'string') {
    return false;
  }

  if (!token || typeof token !== 'string') {
    return false;
  }

  const index = token.indexOf('-');

  if (index === -1) {
    return false;
  }

  const salt = token.slice(0, index);
  const expected = privateTokenize(secret, salt);

  try {
    return timingSafeEqual(Buffer.from(token), Buffer.from(expected));
  } catch {
    return false;
  }
}

export type Options = {
  saltLength?: number;
  secretLength?: number;
};

/**
 * Token generation/verification class.
 */
export default class Tokens {
  private saltLength: number;
  private secretLength: number;

  /**
   * @param [options]
   * @param [options.saltLength=8] The string length of the salt
   * @param [options.secretLength=18] The byte length of the secret key
   */
  constructor(options?: Options) {
    const opts = options ?? {};

    const saltLength = opts.saltLength ?? 8;

    if (typeof saltLength !== 'number' || !Number.isFinite(saltLength) || saltLength < 1) {
      throw new TypeError('option saltLength must be finite number > 1');
    }

    const secretLength = opts.secretLength ?? 18;

    if (typeof secretLength !== 'number' || !Number.isFinite(secretLength) || secretLength < 1) {
      throw new TypeError('option secretLength must be finite number > 1');
    }

    this.saltLength = saltLength;
    this.secretLength = secretLength;
  }

  /**
   * Create a new CSRF token.
   *
   * @param secret The secret for the token.
   */
  create(secret: string): string {
    if (!secret || typeof secret !== 'string') {
      throw new TypeError('argument secret is required');
    }

    // Because a single base64 character encodes 6 bits of information,
    // and one byte contains 8 bits; thus, for example to get 8-symbols long
    // (default) base64 salt string we need to get only 6 random bytes.
    const saltByteLength = Math.ceil(6 * this.saltLength / 8);

    // CAREFUL: The salt is expected (a) to be URL-safe (hence, the "base64url"
    // encoding); (b) contain no "-" (dash) characters (as the first dash in
    // the generated CSRF token is relied upon to split its salt and payload;
    // hence the "-" replacement by "_").
    const salt = randomBytes(saltByteLength)
      .toString('base64url')
      .replace(/-/g, '_')
      .slice(0, this.saltLength);

    return privateTokenize(secret, salt);
  }

  /**
   * Create a new secret key.
   */
  secret(): string {
    return randomBytes(this.secretLength).toString('base64url');
  }
}
