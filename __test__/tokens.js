import assert from 'assert';
import crypto from 'crypto';

import Tokens from '../src/tokens';

let defaultEncoding;
let secret;
let tokens;

describe('Tokens', () => {
  describe('options', () => {
    describe('saltLength', () => {
      it('should reject non-numbers', () => {
        assert.throws(
          () => {
            // eslint-disable-next-line no-new
            new Tokens({ saltLength: 'bogus' });
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
            // eslint-disable-next-line no-new
            new Tokens({ secretLength: 'bogus' });
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
          new Tokens({ secretLength: 3 }).secretSync().length,
          4,
        );
        assert.strictEqual(
          new Tokens({ secretLength: 4 }).secretSync().length,
          6,
        );
      });
    });
  });

  describe('.create(secret)', () => {
    beforeAll(() => {
      tokens = new Tokens();
      secret = tokens.secretSync();
    });

    it('should require secret', () => {
      assert.throws(() => {
        tokens.create();
      }, /argument secret.*required/);
    });

    it('should reject non-string secret', () => {
      assert.throws(() => {
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
        assert(!token.includes('/'));
        assert(!token.includes('+'));
        assert(!token.includes('='));
      }
    });

    describe('when crypto.DEFAULT_ENCODING altered', () => {
      beforeAll(() => {
        defaultEncoding = crypto.DEFAULT_ENCODING;
        crypto.DEFAULT_ENCODING = 'hex';
      });

      afterAll(() => {
        crypto.DEFAULT_ENCODING = defaultEncoding;
      });

      it('should create a token', () => {
        const token = tokens.create(secret);
        assert.ok(typeof token === 'string');
        assert.ok(token.length > 0);
      });
    });
  });

  describe('.secret(callback)', () => {
    beforeAll(() => {
      tokens = new Tokens();
    });

    it('should reject bad callback', () => {
      assert.throws(() => {
        tokens.secret(42);
      }, /argument callback/);
    });

    // eslint-disable-next-line jest/no-done-callback
    it('should create a secret', (done) => {
      tokens.secret((err, localSecret) => {
        assert.ifError(err);
        assert.ok(typeof localSecret === 'string');
        assert.ok(localSecret.length > 0);
        done();
      });
    });
  });

  describe('.secret()', () => {
    beforeAll(() => {
      tokens = new Tokens();
    });

    describe('with global Promise', () => {
      beforeAll(() => {
        // eslint-disable-next-line @babel/no-undef
        global.Promise = Promise;
      });

      afterAll(() => {
        // eslint-disable-next-line @babel/no-undef
        global.Promise = undefined;
      });

      it(
        'should create a secret',
        () => tokens.secret().then((localSecret) => {
          assert.ok(typeof localSecret === 'string');
          assert.ok(localSecret.length > 0);
        }),
      );
    });

    describe('without global Promise', () => {
      beforeAll(() => {
        // eslint-disable-next-line @babel/no-undef
        global.Promise = undefined;
      });

      afterAll(() => {
        // eslint-disable-next-line @babel/no-undef
        global.Promise = Promise;
      });

      it('should require callback', () => {
        assert.throws(() => {
          tokens.secret();
        }, /argument callback.*required/);
      });

      it('should reject bad callback', () => {
        assert.throws(() => {
          tokens.secret(42);
        }, /argument callback/);
      });
    });
  });

  describe('.secretSync()', () => {
    beforeAll(() => {
      tokens = new Tokens();
    });

    it('should create a secret', () => {
      const localSecret = tokens.secretSync();
      assert.ok(typeof localSecret === 'string');
      assert.ok(localSecret.length > 0);
    });
  });

  describe('.verify(secret, token)', () => {
    beforeAll(() => {
      tokens = new Tokens();
      secret = tokens.secretSync();
    });

    it('should return `true` with valid tokens', () => {
      const token = tokens.create(secret);
      assert.ok(Tokens.verify(secret, token));
    });

    it('should return `false` with invalid tokens', () => {
      const token = tokens.create(secret);
      assert.ok(!Tokens.verify(tokens.secretSync(), token));
      assert.ok(!Tokens.verify('asdfasdfasdf', token));
    });

    it('should return `false` with invalid secret', () => {
      assert.ok(!Tokens.verify());
      assert.ok(!Tokens.verify([]));
    });

    it('should return `false` with invalid tokens (2)', () => {
      assert(!Tokens.verify(secret, undefined));
      assert(!Tokens.verify(secret, []));
      assert(!Tokens.verify(secret, 'hi'));
    });
  });
});
