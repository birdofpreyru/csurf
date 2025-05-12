import assert from 'assert';

import Tokens, { verify } from '../src/tokens';

let secret: string;
let tokens: Tokens;

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
        assert(!token.includes('/'));
        assert(!token.includes('+'));
        assert(!token.includes('='));
      }
    });
  });

  describe('.secret(callback)', () => {
    beforeAll(() => {
      tokens = new Tokens();
    });

    it('should reject bad callback', () => {
      assert.throws(async () => {
        // @ts-expect-error "for test purposes"
        await tokens.secret(42);
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
        global.Promise = Promise;
      });

      afterAll(() => {
        // @ts-expect-error "for test purposes"
        global.Promise = undefined;
      });

      it(
        'should create a secret',
        async () => tokens.secret().then((localSecret) => {
          assert.ok(typeof localSecret === 'string');
          assert.ok(localSecret.length > 0);
        }),
      );
    });

    describe('without global Promise', () => {
      beforeAll(() => {
        // @ts-expect-error "for test purposes"
        global.Promise = undefined;
      });

      afterAll(() => {
        global.Promise = Promise;
      });

      it('should require callback', () => {
        assert.throws(async () => {
          await tokens.secret();
        }, /argument callback.*required/);
      });

      it('should reject bad callback', () => {
        assert.throws(async () => {
          // @ts-expect-error "for test purposes"
          await tokens.secret(42);
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
      assert.ok(verify(secret, token));
    });

    it('should return `false` with invalid tokens', () => {
      const token = tokens.create(secret);
      assert.ok(!verify(tokens.secretSync(), token));
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
