const rndm = require('rndm');
const uid = require('uid-safe');
const compare = require('tsscmp');
const crypto = require('crypto');

const EQUAL_GLOBAL_REGEXP = /=/g;
const PLUS_GLOBAL_REGEXP = /\+/g;
const SLASH_GLOBAL_REGEXP = /\//g;

/**
 * Hash a string with SHA256, returning url-safe base64
 * @param {string} str
 * @private
 */
function hash(str) {
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
function privateTokenize(secret, salt) {
  return `${salt}-${hash(`${salt}-${secret}`)}`;
}

/**
 * Verify if a given token is valid for a given secret.
 *
 * @param {string} secret
 * @param {string} token
 */
function verify(secret, token) {
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

/**
 * Token generation/verification class.
 */
class Tokens {
  /**
   * @param {object} [options]
   * @param {number} [options.saltLength=8] The string length of the salt
   * @param {number} [options.secretLength=18] The byte length of the secret key
   */
  constructor(options) {
    const opts = options || {};

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
   * @param {string} secret The secret for the token.
   */
  create(secret) {
    if (!secret || typeof secret !== 'string') {
      throw new TypeError('argument secret is required');
    }

    return privateTokenize(secret, rndm(this.saltLength));
  }

  /**
   * Create a new secret key.
   *
   * @param {function} [callback]
   */
  secret(callback) {
    return uid(this.secretLength, callback);
  }

  /**
   * Create a new secret key synchronously.
   */
  secretSync() {
    return uid.sync(this.secretLength);
  }
}

/**
 * Module exports.
 */
module.exports = Tokens;

module.exports.verify = verify;
