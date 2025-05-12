import type { NextFunction, Request, Response } from 'express';

import { type SerializeOptions, serialize } from 'cookie';
import createError from 'http-errors';
import { sign } from 'cookie-signature';
import Tokens, { type Options as TokensOptions, verify } from './tokens';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    // eslint-disable-next-line @typescript-eslint/consistent-type-definitions
    interface Request {
      // The CSRF token generation routine, added by this library.
      csrfToken: () => string;

      // Cookie-signature secret, configured and set by "cookie-parser" middleware,
      // if that is configured to support signed cookies:
      // https://github.com/expressjs/cookie-parser
      secret?: string;
    }
  }
}

// TODO: This should come from a cookie library.
type CookieOptions = {
  domain?: string;
  httpOnly?: boolean;
  key: string;
  maxAge?: number;
  path: string;
  sameSite?: 'lax' | 'none' | 'strict' | true;
  secure?: boolean;
  signed?: boolean;
};

export type Options = TokensOptions & {
  cookie?: true | CookieOptions;
  ignoreMethods?: string[];
  sessionKey?: string;
  value?: (req: Request) => string;
};

/**
 * Get options for cookie.
 *
 * @param {boolean|object} [options]
 */
function getCookieOptions(
  options: boolean | Partial<CookieOptions> | undefined,
): CookieOptions | undefined {
  if (options !== true && typeof options !== 'object') {
    return undefined;
  }

  const opts: CookieOptions = {
    key: '_csrf',
    path: '/',
  };

  if (typeof options === 'object') {
    for (const [key, value] of Object.entries(options)) {
      // TODO: It actually breaks one of existing tests, if we don't check
      // for it. Perhaps, we should correct typings, or do some other refactoring
      // to avoid this.
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
      if (value !== undefined) {
        (opts[key as keyof CookieOptions] as unknown) = value;
      }
    }
  }

  return opts;
}

/**
 * Default value function, checking the `req.body`
 * and `req.query` for the CSRF token.
 *
 * @param req
 * @return
 */
function defaultValue(req: Request<unknown, unknown, undefined | {
  _csrf?: string;
}, undefined | {
  _csrf?: string;
}>): string {
  /* eslint-disable @typescript-eslint/prefer-nullish-coalescing */
  // eslint-disable-next-line no-underscore-dangle
  return (req.body?._csrf || req.query?._csrf
    || req.headers['csrf-token']
    || req.headers['xsrf-token']
    || req.headers['x-csrf-token']
    || req.headers['x-xsrf-token']) as string;
  /* eslint-enable @typescript-eslint/prefer-nullish-coalescing */
}

// TODO: Actually, we should type `methods` stricter, limiting it to the valid
// method name literals.
/**
 * Get a lookup of ignored methods.
 *
 * @param {array} methods
 * @returns {object}
 * @api private
 */
function getIgnoredMethods(methods: string[]): Record<string, true> {
  const obj: Record<string, true> = {};

  for (const method of methods) {
    obj[method.toUpperCase()] = true;
  }

  return obj;
}

type SecretBag = Record<string, string>;

/**
 * Get the token secret bag from the request.
 *
 * @param {IncomingMessage} req
 * @param {String} sessionKey
 * @param {Object} [cookie]
 * @api private
 */
function getSecretBag(
  req: Request,
  sessionKey: string,
  cookie: CookieOptions | undefined,
): SecretBag | undefined {
  if (cookie) {
    // get secret from cookie
    const cookieKey = cookie.signed
      ? 'signedCookies'
      : 'cookies';

    return req[cookieKey] as SecretBag;
  }

  // TODO: A less forceful type casting would be nice to have here.
  // get secret from session
  return (req as unknown as Record<string, unknown>)[sessionKey] as SecretBag;
}

/**
 * Get the token secret from the request.
 *
 * @param {IncomingMessage} req
 * @param {String} sessionKey
 * @param {Object} [cookie]
 * @api private
 */
function getSecret(
  req: Request,
  sessionKey: string,
  cookie: CookieOptions | undefined,
) {
  // get the bag & key
  const bag = getSecretBag(req, sessionKey, cookie);
  // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
  const key = cookie?.key || 'csrfSecret';

  if (!bag) {
    throw new Error('misconfigured csrf');
  }

  // return secret from bag
  return bag[key];
}

/**
 * Set a cookie on the HTTP response.
 *
 * @param {OutgoingMessage} res
 * @param {string} name
 * @param {string} val
 * @param {Object} [options]
 * @api private
 */
function setCookie(
  res: Response,
  name: string,
  val: string,
  options: SerializeOptions,
) {
  const data = serialize(name, val, options);
  // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
  const rawPrev = res.getHeader('set-cookie') || [];
  const prev = typeof rawPrev === 'number' ? rawPrev.toString() : rawPrev;
  const header = Array.isArray(prev) ? prev.concat(data)
    : [prev, data];

  res.setHeader('set-cookie', header);
}

/**
 * Set the token secret on the request.
 *
 * @param {IncomingMessage} req
 * @param {OutgoingMessage} res
 * @param {string} sessionKey
 * @param {string} val
 * @param {Object} [cookie]
 * @api private
 */
function setSecret(
  req: Request,
  res: Response,
  sessionKey: string,
  val: string,
  cookie?: CookieOptions,
) {
  if (cookie) {
    // set secret on cookie
    let value = val;

    if (cookie.signed) {
      // NOTE: This one is not expected to be hit, as if the cookie signature
      // secret is not properly configured via "cookie-parser" middleware, that
      // is checked and throws earlier in the code.
      if (!req.secret) throw Error('Internal error');

      value = `s:${sign(val, req.secret)}`;
    }

    setCookie(res, cookie.key, value, cookie);
  } else {
    // set secret on session
    // TODO: Can we type it in a better way, to avoid such forced type-cast?
    // eslint-disable-next-line no-param-reassign
    (req as unknown as Record<string, { csrfSecret: string }>)[sessionKey]!
      .csrfSecret = val;
  }
}

/**
 * Verify the configuration against the request.
 * @private
 */
function verifyConfiguration(
  req: Request,
  sessionKey: string,
  cookie: CookieOptions | undefined,
): boolean {
  if (!getSecretBag(req, sessionKey, cookie)) {
    return false;
  }

  // NOTE: `req.secret` is the cookie signature secret, configured and set by
  // "cookie-parser" middleware: https://github.com/expressjs/cookie-parser
  if (cookie && cookie.signed && !req.secret) {
    return false;
  }

  return true;
}

/**
 * CSRF protection middleware.
 *
 * This middleware adds a `req.csrfToken()` function to make a token
 * which should be added to requests which mutate
 * state, within a hidden form field, query-string etc. This
 * token is validated against the visitor's session.
 *
 * @param {Object} options
 * @return {Function} middleware
 * @public
 */
function csurf(options: Options = {}) {
  // get cookie options
  const cookie = getCookieOptions(options.cookie);

  // get session options
  // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
  const sessionKey = options.sessionKey || 'session';

  // get value getter
  // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
  const value = options.value || defaultValue;

  // token repo
  const tokens = new Tokens(options);

  // ignored methods
  const ignoreMethods = options.ignoreMethods ?? ['GET', 'HEAD', 'OPTIONS'];

  if (!Array.isArray(ignoreMethods)) {
    throw new TypeError('option ignoreMethods must be an array');
  }

  // generate lookup
  const ignoreMethod = getIgnoredMethods(ignoreMethods);

  return (req: Request, res: Response, next: NextFunction): void => {
    // validate the configuration against request
    if (!verifyConfiguration(req, sessionKey, cookie)) {
      next(new Error('misconfigured csrf'));
      return;
    }

    // get the secret from the request
    let secret = getSecret(req, sessionKey, cookie);
    let token: string;

    // lazy-load token getter
    // eslint-disable-next-line no-param-reassign
    req.csrfToken = () => {
      let sec = cookie ? secret : getSecret(req, sessionKey, cookie);

      // use cached token if secret has not changed
      if (token && sec === secret) {
        return token;
      }

      // generate & set new secret
      if (sec === undefined) {
        sec = tokens.secretSync();
        setSecret(req, res, sessionKey, sec, cookie);
      }

      // update changed secret
      secret = sec;

      // create new token
      token = tokens.create(secret);

      return token;
    };

    // generate & set secret
    if (!secret) {
      secret = tokens.secretSync();
      setSecret(req, res, sessionKey, secret, cookie);
    }

    // verify the incoming token
    if (!ignoreMethod[req.method] && !verify(secret, value(req))) {
      next(createError(403, 'invalid csrf token', {
        code: 'EBADCSRFTOKEN',
      }));
      return;
    }

    next();
  };
}

export default csurf;
