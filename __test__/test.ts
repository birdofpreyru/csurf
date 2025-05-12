import assert from 'assert';

import express, {
  type Express,
  type NextFunction,
  type Request,
  type Response,
} from 'express';

import { createServer as createHttpServer } from 'http';
import session from 'cookie-session';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import request, { type Response as SuperResponse } from 'supertest';

import csurf, { type Options } from '../src';

function createServer(opts?: Options) {
  const app = express();

  if (!opts || !opts.cookie) {
    app.use(session({ keys: ['a', 'b'] }) as () => void);
  } else {
    app.use(cookieParser('keyboard cat') as () => void);
  }

  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(csurf(opts));

  app.use((req, res) => {
    res.end(req.csrfToken() || 'none');
  });

  // TODO: What is the best way to avoid type mismatch here?
  // eslint-disable-next-line @typescript-eslint/no-misused-promises
  return createHttpServer(app);
}

function cookie(res: SuperResponse, name: string): string {
  return (res.get('set-cookie') as string[] | undefined)!
    .find((items) => items.split('=')[0] === name)!;
}

function cookies(res: SuperResponse) {
  return (res.get('set-cookie') as string[] | undefined)!
    .map((items) => items.split(';')[0]).join(';');
}

describe('csurf', () => {
  // eslint-disable-next-line jest/no-done-callback
  it('should work in req.body', (done) => {
    const server = createServer();

    request(server)
      .get('/')
      .expect(200, (err: unknown, res) => {
        // eslint-disable-next-line jest/no-conditional-in-test
        if (err) {
          done(err);
          return;
        }
        const token = res.text;

        request(server)
          .post('/')
          .set('Cookie', cookies(res))
          .send(`_csrf=${encodeURIComponent(token)}`)
          .expect(200, done);
      });
  });

  // eslint-disable-next-line jest/no-done-callback
  it('should work in req.query', (done) => {
    const server = createServer();

    request(server)
      .get('/')
      .expect(200, (err, res) => {
        // eslint-disable-next-line jest/no-conditional-in-test
        if (err) {
          done(err);
          return;
        }
        const token = res.text;

        request(server)
          .post(`/?_csrf=${encodeURIComponent(token)}`)
          .set('Cookie', cookies(res))
          .expect(200, done);
      });
  });

  // eslint-disable-next-line jest/no-done-callback
  it('should work in csrf-token header', (done) => {
    const server = createServer();

    request(server)
      .get('/')
      .expect(200, (err, res) => {
        // eslint-disable-next-line jest/no-conditional-in-test
        if (err) {
          done(err);
          return;
        }
        const token = res.text;

        request(server)
          .post('/')
          .set('Cookie', cookies(res))
          .set('csrf-token', token)
          .expect(200, done);
      });
  });

  // eslint-disable-next-line jest/no-done-callback
  it('should work in xsrf-token header', (done) => {
    const server = createServer();

    request(server)
      .get('/')
      .expect(200, (err, res) => {
        // eslint-disable-next-line jest/no-conditional-in-test
        if (err) {
          done(err);
          return;
        }
        const token = res.text;

        request(server)
          .post('/')
          .set('Cookie', cookies(res))
          .set('xsrf-token', token)
          .expect(200, done);
      });
  });

  // eslint-disable-next-line jest/no-done-callback
  it('should work in x-csrf-token header', (done) => {
    const server = createServer();

    request(server)
      .get('/')
      .expect(200, (err, res) => {
        // eslint-disable-next-line jest/no-conditional-in-test
        if (err) {
          done(err);
          return;
        }
        const token = res.text;

        request(server)
          .post('/')
          .set('Cookie', cookies(res))
          .set('x-csrf-token', token)
          .expect(200, done);
      });
  });

  // eslint-disable-next-line jest/no-done-callback
  it('should work in x-xsrf-token header', (done) => {
    const server = createServer();

    request(server)
      .get('/')
      .expect(200, (err, res) => {
        // eslint-disable-next-line jest/no-conditional-in-test
        if (err) {
          done(err);
          return;
        }
        const token = res.text;

        request(server)
          .post('/')
          .set('Cookie', cookies(res))
          .set('x-xsrf-token', token)
          .expect(200, done);
      });
  });

  // eslint-disable-next-line jest/no-done-callback
  it('should fail with an invalid token', (done) => {
    const server = createServer();

    request(server)
      .get('/')
      .expect(200, (err, res) => {
        // eslint-disable-next-line jest/no-conditional-in-test
        if (err) {
          done(err);
          return;
        }
        request(server)
          .post('/')
          .set('Cookie', cookies(res))
          .set('X-CSRF-Token', '42')
          .expect(403, done);
      });
  });

  // eslint-disable-next-line jest/no-done-callback
  it('should fail with no token', (done) => {
    const server = createServer();

    request(server)
      .get('/')
      .expect(200, (err, res) => {
        // eslint-disable-next-line jest/no-conditional-in-test
        if (err) {
          done(err);
          return;
        }
        request(server)
          .post('/')
          .set('Cookie', cookies(res))
          .expect(403, done);
      });
  });

  // eslint-disable-next-line jest/no-done-callback
  it('should provide error code on invalid token error', (done) => {
    const app = express();
    app.use(session({ keys: ['a', 'b'] }));
    app.use(csurf());

    app.use((req, res) => {
      // eslint-disable-next-line jest/no-conditional-in-test
      res.end(req.csrfToken() || 'none');
    });

    app.use(
      (
        err: { code?: string },
        req: Request,
        res: Response,
        next: NextFunction,
      ) => {
        // eslint-disable-next-line jest/no-conditional-in-test
        if (err.code !== 'EBADCSRFTOKEN') {
          next(err);
          return;
        }
        // eslint-disable-next-line no-param-reassign
        res.statusCode = 403;
        res.end('session has expired or form tampered with');
      },
    );

    request(app)
      .get('/')
      .expect(200, (err, res) => {
        // eslint-disable-next-line jest/no-conditional-in-test
        if (err) {
          done(err);
          return;
        }
        request(app)
          .post('/')
          .set('Cookie', cookies(res))
          .set('X-CSRF-Token', `${res.text}p`)
          .expect(403, 'session has expired or form tampered with', done);
      });
  });

  // eslint-disable-next-line jest/no-done-callback
  it('should error without session secret storage', (done) => {
    const app = express();

    app.use(csurf());

    request(app)
      .get('/')
      .expect(500, /misconfigured csrf/, done);
  });

  describe('with "cookie" option', () => {
    describe('when true', () => {
      // eslint-disable-next-line jest/no-done-callback
      it('should store secret in "_csrf" cookie', (done) => {
        const server = createServer({ cookie: true });

        request(server)
          .get('/')
          .expect(200, (err, res) => {
            // eslint-disable-next-line jest/no-conditional-in-test
            if (err) {
              done(err);
              return;
            }
            const data = cookie(res, '_csrf');
            const token = res.text;

            assert.ok(Boolean(data));
            assert.ok((/; *path=\/(?:;|$)/i).test(data));

            request(server)
              .post('/')
              .set('Cookie', cookies(res))
              .set('X-CSRF-Token', token)
              .expect(200, done);
          });
      });

      // eslint-disable-next-line jest/no-done-callback
      it('should append cookie to existing Set-Cookie header', (done) => {
        const app = express();

        app.use(cookieParser('keyboard cat'));
        app.use((req, res, next) => {
          res.setHeader('Set-Cookie', 'foo=bar');
          next();
        });
        app.use(csurf({ cookie: true }));
        app.use((req, res) => {
          // eslint-disable-next-line jest/no-conditional-in-test
          res.end(req.csrfToken() || 'none');
        });

        request(app)
          .get('/')
          .expect(200, (err, res) => {
            // eslint-disable-next-line jest/no-conditional-in-test
            if (err) {
              done(err);
              return;
            }
            const token = res.text;

            assert.ok(Boolean(cookie(res, '_csrf')));
            assert.ok(Boolean(cookie(res, 'foo')));

            request(app)
              .post('/')
              .set('Cookie', cookies(res))
              .set('X-CSRF-Token', token)
              .expect(200, done);
          });
      });
    });

    describe('when an object', () => {
      // eslint-disable-next-line jest/no-done-callback
      it('should configure the cookie name with "key"', (done) => {
        // @ts-expect-error "error for test purposes"
        const server = createServer({ cookie: { key: '_customcsrf' } });

        request(server)
          .get('/')
          .expect(200, (err, res) => {
            // eslint-disable-next-line jest/no-conditional-in-test
            if (err) {
              done(err);
              return;
            }
            const data = cookie(res, '_customcsrf');
            const token = res.text;

            assert.ok(Boolean(data));
            assert.ok((/; *path=\/(?:;|$)/i).test(data));

            request(server)
              .post('/')
              .set('Cookie', cookies(res))
              .set('X-CSRF-Token', token)
              .expect(200, done);
          });
      });

      // eslint-disable-next-line jest/no-done-callback
      it('should keep default cookie name when "key: undefined"', (done) => {
        // @ts-expect-error "error for test purposes"
        const server = createServer({ cookie: { key: undefined } });

        request(server)
          .get('/')
          .expect(200, (err, res) => {
            // eslint-disable-next-line jest/no-conditional-in-test
            if (err) {
              done(err);
              return;
            }
            const data = cookie(res, '_csrf');
            const token = res.text;

            assert.ok(Boolean(data));
            assert.ok((/; *path=\/(?:;|$)/i).test(data));

            request(server)
              .post('/')
              .set('Cookie', cookies(res))
              .set('X-CSRF-Token', token)
              .expect(200, done);
          });
      });

      describe('when "signed": true', () => {
        // eslint-disable-next-line jest/no-done-callback
        it('should enable signing', (done) => {
          // @ts-expect-error "error for test purposes"
          const server = createServer({ cookie: { signed: true } });

          request(server)
            .get('/')
            .expect(200, (err, res) => {
              // eslint-disable-next-line jest/no-conditional-in-test
              if (err) {
                done(err);
                return;
              }
              const data = cookie(res, '_csrf');
              const token = res.text;

              assert.ok(Boolean(data));
              assert.ok((/^_csrf=s%3A/i).test(data));

              request(server)
                .post('/')
                .set('Cookie', cookies(res))
                .set('X-CSRF-Token', token)
                .expect(200, done);
            });
        });

        // eslint-disable-next-line jest/no-done-callback
        it('should error without cookieParser', (done) => {
          const app = express();

          // @ts-expect-error "error for test purposes"
          app.use(csurf({ cookie: { signed: true } }));

          request(app)
            .get('/')
            .expect(500, /misconfigured csrf/, done);
        });

        // eslint-disable-next-line jest/no-done-callback
        it('should error when cookieParser is missing secret', (done) => {
          const app = express();

          app.use(cookieParser());
          // @ts-expect-error "error for test purposes"
          app.use(csurf({ cookie: { signed: true } }));

          request(app)
            .get('/')
            .expect(500, /misconfigured csrf/, done);
        });
      });
    });
  });

  describe('with "ignoreMethods" option', () => {
    it('should reject invalid value', () => {
      // @ts-expect-error "error for test purposes"
      assert.throws(createServer.bind(null, { ignoreMethods: 'tj' }), /option ignoreMethods/);
    });

    // eslint-disable-next-line jest/no-done-callback
    it('should not check token on given methods', (done) => {
      const server = createServer({ ignoreMethods: ['GET', 'POST'] });

      request(server)
        .get('/')
        .expect(200, (err, res) => {
          // eslint-disable-next-line jest/no-conditional-in-test
          if (err) {
            done(err);
            return;
          }
          const cookie2 = cookies(res);
          request(server)
            .post('/')
            .set('Cookie', cookie2)
            .expect(200, (err2) => {
              // eslint-disable-next-line jest/no-conditional-in-test
              if (err2) {
                done(err2);
                return;
              }
              request(server)
                .put('/')
                .set('Cookie', cookie2)
                .expect(403, done);
            });
        });
    });
  });

  describe('with "sessionKey" option', () => {
    // eslint-disable-next-line jest/no-done-callback
    it('should use the specified sessionKey', (done) => {
      const app = express();
      const sess = {};

      app.use((req, res, next) => {
        // @ts-expect-error "error for test purposes"
        req.mySession = sess; // eslint-disable-line no-param-reassign
        next();
      });
      app.use(bodyParser.urlencoded({ extended: false }));
      app.use(csurf({ sessionKey: 'mySession' }));
      app.use((req, res) => {
        // eslint-disable-next-line jest/no-conditional-in-test
        res.end(req.csrfToken() || 'none');
      });

      request(app)
        .get('/')
        .expect(200, (err, res) => {
          // eslint-disable-next-line jest/no-conditional-in-test
          if (err) {
            done(err);
            return;
          }
          const token = res.text;

          request(app)
            .post('/')
            .send(`_csrf=${encodeURIComponent(token)}`)
            .expect(200, done);
        });
    });
  });

  describe('req.csrfToken()', () => {
    // eslint-disable-next-line jest/no-done-callback
    it('should return same token for each call', (done) => {
      const app = express();
      app.use(session({ keys: ['a', 'b'] }));
      app.use(csurf());
      app.use((req, res) => {
        const token1 = req.csrfToken();
        const token2 = req.csrfToken();
        res.end(String(token1 === token2));
      });

      request(app)
        .get('/')
        .expect(200, 'true', done);
    });

    // eslint-disable-next-line jest/no-done-callback
    it('should error when secret storage missing', (done) => {
      const app = express();

      app.use(session({ keys: ['a', 'b'] }));
      app.use(csurf());
      app.use((req, res) => {
        // eslint-disable-next-line no-param-reassign
        req.session = null;
        res.setHeader('x-run', 'true');
        res.end(req.csrfToken());
      });

      request(app)
        .get('/')
        .expect('x-run', 'true')
        .expect(500, /misconfigured csrf/, done);
    });
  });

  describe('when using session storage', () => {
    let app: Express;

    beforeAll(() => {
      app = express();
      app.use(session({ keys: ['a', 'b'] }));
      app.use(csurf());
      app.use('/break', (req, res, next) => {
        // break session
        // eslint-disable-next-line no-param-reassign
        req.session = null;
        next();
      });
      app.use('/new', (req, res, next) => {
        // regenerate session
        // eslint-disable-next-line no-param-reassign
        req.session = { hit: 1 };
        next();
      });
      app.use((req, res) => {
        res.end(req.csrfToken() || 'none');
      });
    });

    // eslint-disable-next-line jest/no-done-callback
    it('should work with a valid token', (done) => {
      request(app)
        .get('/')
        .expect(200, (err, res) => {
          // eslint-disable-next-line jest/no-conditional-in-test
          if (err) {
            done(err);
            return;
          }
          const token = res.text;
          request(app)
            .post('/')
            .set('Cookie', cookies(res))
            .set('X-CSRF-Token', token)
            .expect(200, done);
        });
    });

    // eslint-disable-next-line jest/no-done-callback
    it('should provide a valid token when session regenerated', (done) => {
      request(app)
        .get('/new')
        .expect(200, (err, res) => {
          // eslint-disable-next-line jest/no-conditional-in-test
          if (err) {
            done(err);
            return;
          }
          const token = res.text;
          request(app)
            .post('/')
            .set('Cookie', cookies(res))
            .set('X-CSRF-Token', token)
            .expect(200, done);
        });
    });

    // eslint-disable-next-line jest/no-done-callback
    it('should error if session missing', (done) => {
      request(app)
        .get('/break')
        .expect(500, /misconfigured csrf/, done);
    });
  });
});
