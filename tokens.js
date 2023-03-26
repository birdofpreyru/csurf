/*!
 * csrf
 * Copyright(c) 2014 Jonathan Ong
 * Copyright(c) 2015 Douglas Christopher Wilson
 * MIT Licensed
 */

/**
 * Module dependencies.
 * @private
 */

const rndm = require('rndm');
const uid = require('uid-safe');
const compare = require('tsscmp');
const crypto = require('crypto');

/**
 * Module variables.
 * @private
 */

const EQUAL_GLOBAL_REGEXP = /=/g;
const PLUS_GLOBAL_REGEXP = /\+/g;
const SLASH_GLOBAL_REGEXP = /\//g;

/**
 * Hash a string with SHA1, returning url-safe base64
 * @param {string} str
 * @private
 */

function hash(str) {
  return crypto
    .createHash('sha1')
    .update(str, 'ascii')
    .digest('base64')
    .replace(PLUS_GLOBAL_REGEXP, '-')
    .replace(SLASH_GLOBAL_REGEXP, '_')
    .replace(EQUAL_GLOBAL_REGEXP, '');
}

/**
 * Token generation/verification class.
 *
 * @param {object} [options]
 * @param {number} [options.saltLength=8] The string length of the salt
 * @param {number} [options.secretLength=18] The byte length of the secret key
 * @public
 */

function Tokens(options) {
  if (!(this instanceof Tokens)) {
    return new Tokens(options);
  }

  const opts = options || {};

  const saltLength = opts.saltLength !== undefined
    ? opts.saltLength
    : 8;

  if (typeof saltLength !== 'number' || !Number.isFinite(saltLength) || saltLength < 1) {
    throw new TypeError('option saltLength must be finite number > 1');
  }

  const secretLength = opts.secretLength !== undefined
    ? opts.secretLength
    : 18;

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
 * @public
 */

Tokens.prototype.create = function create(secret) {
  if (!secret || typeof secret !== 'string') {
    throw new TypeError('argument secret is required');
  }

  return this.privateTokenize(secret, rndm(this.saltLength));
};

/**
 * Create a new secret key.
 *
 * @param {function} [callback]
 * @public
 */

Tokens.prototype.secret = function secret(callback) {
  return uid(this.secretLength, callback);
};

/**
 * Create a new secret key synchronously.
 * @public
 */

Tokens.prototype.secretSync = function secretSync() {
  return uid.sync(this.secretLength);
};

/**
 * Tokenize a secret and salt.
 * @private
 */

Tokens.prototype.privateTokenize = function tokenize(secret, salt) {
  return `${salt}-${hash(`${salt}-${secret}`)}`;
};

/**
 * Verify if a given token is valid for a given secret.
 *
 * @param {string} secret
 * @param {string} token
 * @public
 */

Tokens.prototype.verify = function verify(secret, token) {
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
  const expected = this.privateTokenize(secret, salt);

  return compare(token, expected);
};

/**
 * Module exports.
 * @public
 */

module.exports = Tokens;
