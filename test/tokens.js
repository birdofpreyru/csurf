const assert = require('assert');
const crypto = require('crypto');

const { Promise } = global;
const Tokens = require('../tokens');

// Add Promise to mocha's global list
// eslint-disable-next-line no-self-assign
global.Promise = global.Promise;

describe('Tokens', () => {
  describe('options', () => {
    describe('saltLength', () => {
      it('should reject non-numbers', () => {
        assert.throws(
          Tokens.bind(null, { saltLength: 'bogus' }),
          /option saltLength/,
        );
      });

      it('should reject NaN', () => {
        assert.throws(
          Tokens.bind(null, { saltLength: NaN }),
          /option saltLength/,
        );
      });

      it('should reject Infinity', () => {
        assert.throws(
          Tokens.bind(null, { saltLength: Infinity }),
          /option saltLength/,
        );
      });
    });

    describe('secretLength', () => {
      it('should reject non-numbers', () => {
        assert.throws(
          Tokens.bind(null, { secretLength: 'bogus' }),
          /option secretLength/,
        );
      });

      it('should reject NaN', () => {
        assert.throws(
          Tokens.bind(null, { secretLength: NaN }),
          /option secretLength/,
        );
      });

      it('should reject Infinity', () => {
        assert.throws(
          Tokens.bind(null, { secretLength: Infinity }),
          /option secretLength/,
        );
      });

      it('should generate secret with specified byte length', () => {
        // 3 bytes = 4 base-64 characters
        // 4 bytes = 6 base-64 characters
        assert.strictEqual(Tokens({ secretLength: 3 }).secretSync().length, 4);
        assert.strictEqual(Tokens({ secretLength: 4 }).secretSync().length, 6);
      });
    });
  });

  describe('.create(secret)', () => {
    before(() => {
      this.tokens = new Tokens();
      this.secret = this.tokens.secretSync();
    });

    it('should require secret', () => {
      assert.throws(() => {
        this.tokens.create();
      }, /argument secret.*required/);
    });

    it('should reject non-string secret', () => {
      assert.throws(() => {
        this.tokens.create(42);
      }, /argument secret.*required/);
    });

    it('should reject empty string secret', () => {
      assert.throws(() => {
        this.tokens.create('');
      }, /argument secret.*required/);
    });

    it('should create a token', () => {
      const token = this.tokens.create(this.secret);
      assert.ok(typeof token === 'string');
    });

    it('should always be the same length', () => {
      const token = this.tokens.create(this.secret);
      assert.ok(token.length > 0);

      for (let i = 0; i < 1000; i++) {
        assert.strictEqual(this.tokens.create(this.secret).length, token.length);
      }
    });

    it('should not contain /, +, or =', () => {
      for (let i = 0; i < 1000; i++) {
        const token = this.tokens.create(this.secret);
        assert(!token.includes('/'));
        assert(!token.includes('+'));
        assert(!token.includes('='));
      }
    });

    describe('when crypto.DEFAULT_ENCODING altered', () => {
      before(() => {
        this.defaultEncoding = crypto.DEFAULT_ENCODING;
        crypto.DEFAULT_ENCODING = 'hex';
      });

      after(() => {
        crypto.DEFAULT_ENCODING = this.defaultEncoding;
      });

      it('should create a token', () => {
        const token = this.tokens.create(this.secret);
        assert.ok(typeof token === 'string');
        assert.ok(token.length > 0);
      });
    });
  });

  describe('.secret(callback)', () => {
    before(() => {
      this.tokens = new Tokens();
    });

    it('should reject bad callback', () => {
      assert.throws(() => {
        this.tokens.secret(42);
      }, /argument callback/);
    });

    it('should create a secret', (done) => {
      this.tokens.secret((err, secret) => {
        assert.ifError(err);
        assert.ok(typeof secret === 'string');
        assert.ok(secret.length > 0);
        done();
      });
    });
  });

  describe('.secret()', () => {
    before(() => {
      this.tokens = new Tokens();
    });

    describe('with global Promise', () => {
      before(() => {
        global.Promise = Promise;
      });

      after(() => {
        global.Promise = undefined;
      });

      it(
        'should create a secret',
        () => this.tokens.secret().then((secret) => {
          assert.ok(typeof secret === 'string');
          assert.ok(secret.length > 0);
        }),
      );
    });

    describe('without global Promise', () => {
      before(() => {
        global.Promise = undefined;
      });

      after(() => {
        global.Promise = Promise;
      });

      it('should require callback', () => {
        assert.throws(() => {
          this.tokens.secret();
        }, /argument callback.*required/);
      });

      it('should reject bad callback', () => {
        assert.throws(() => {
          this.tokens.secret(42);
        }, /argument callback/);
      });
    });
  });

  describe('.secretSync()', () => {
    before(() => {
      this.tokens = new Tokens();
    });

    it('should create a secret', () => {
      const secret = this.tokens.secretSync();
      assert.ok(typeof secret === 'string');
      assert.ok(secret.length > 0);
    });
  });

  describe('.verify(secret, token)', () => {
    before(() => {
      this.tokens = new Tokens();
      this.secret = this.tokens.secretSync();
    });

    it('should return `true` with valid tokens', () => {
      const token = this.tokens.create(this.secret);
      assert.ok(this.tokens.verify(this.secret, token));
    });

    it('should return `false` with invalid tokens', () => {
      const token = this.tokens.create(this.secret);
      assert.ok(!this.tokens.verify(this.tokens.secretSync(), token));
      assert.ok(!this.tokens.verify('asdfasdfasdf', token));
    });

    it('should return `false` with invalid secret', () => {
      assert.ok(!this.tokens.verify());
      assert.ok(!this.tokens.verify([]));
    });

    it('should return `false` with invalid tokens', () => {
      assert(!this.tokens.verify(this.secret, undefined));
      assert(!this.tokens.verify(this.secret, []));
      assert(!this.tokens.verify(this.secret, 'hi'));
    });
  });
});
