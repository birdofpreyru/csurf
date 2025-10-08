import crypto from 'node:crypto';

import rndm from 'rndm';
import uid from 'uid-safe';
import compare from 'tsscmp';

const EQUAL_GLOBAL_REGEXP = /=/g;
const PLUS_GLOBAL_REGEXP = /\+/g;
const SLASH_GLOBAL_REGEXP = /\//g;

/**
 * Hash a string with SHA256, returning url-safe base64.
 */
function hash(str: string): string {
  return crypto
    .createHash('sha256')
    .update(str, 'ascii')
    .digest('base64')
    .replace(PLUS_GLOBAL_REGEXP, '-')
    .replace(SLASH_GLOBAL_REGEXP, '_')
    .replace(EQUAL_GLOBAL_REGEXP, '');
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

  return compare(token, expected);
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

    return privateTokenize(secret, rndm(this.saltLength));
  }

  secret(): Promise<string>;
  secret(callback: (err: unknown, str: string) => void): void;

  /**
   * Create a new secret key.
   */
  secret(
    callback?: (err: unknown, str: string) => void,
  ): Promise<string> | undefined {
    if (callback) {
      uid(this.secretLength, callback);
      return undefined;
    }

    return uid(this.secretLength);
  }

  /**
   * Create a new secret key synchronously.
   */
  secretSync(): string {
    return uid.sync(this.secretLength);
  }
}
