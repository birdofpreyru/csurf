declare namespace Express {
  import type { Request } from 'express';

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
