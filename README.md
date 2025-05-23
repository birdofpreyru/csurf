# CSURF

[![Latest NPM Release](https://img.shields.io/npm/v/@dr.pogodin/csurf.svg)](https://www.npmjs.com/package/@dr.pogodin/csurf)
[![NPM Downloads](https://img.shields.io/npm/dm/@dr.pogodin/csurf.svg)](https://www.npmjs.com/package/@dr.pogodin/csurf)
[![CircleCI](https://dl.circleci.com/status-badge/img/gh/birdofpreyru/csurf/tree/master.svg?style=shield)](https://app.circleci.com/pipelines/github/birdofpreyru/csurf)
[![GitHub Repo stars](https://img.shields.io/github/stars/birdofpreyru/csurf?style=social)](https://github.com/birdofpreyru/csurf)
[![Dr. Pogodin Studio](https://raw.githubusercontent.com/birdofpreyru/csurf/master/.README/logo-dr-pogodin-studio.svg)](https://dr.pogodin.studio/docs/csurf)

Node.js [CSRF][wikipedia-csrf] protection middleware for [ExpressJS].

[![Sponsor](https://raw.githubusercontent.com/birdofpreyru/csurf/master/.README/sponsor.svg)](https://github.com/sponsors/birdofpreyru)

### [Contributors](https://github.com/birdofpreyru/csurf/graphs/contributors)
[<img width=36 src="https://avatars.githubusercontent.com/u/33452?v=4&s=36" />](https://github.com/pietia)
[<img width=36 src="https://avatars.githubusercontent.com/u/818316?v=4&s=36" />](https://github.com/bchew)
[<img width=36 src="https://avatars.githubusercontent.com/u/8205343?v=4&s=36" />](https://github.com/mattbaileyuk)
[<img width=36 src="https://avatars.githubusercontent.com/u/20144632?s=36" />](https://github.com/birdofpreyru)
<br />[+ contributors of the original `csurf`](https://github.com/expressjs/csurf/graphs/contributors)

---
_This is a fork of the original [csurf] package which was deprecated by its author with doubtful reasoning (in the nutshell the package was alright, but author did not want to maintain it anymore). It is published to NPM as [@dr.pogodin/csurf], its version **1.11.0** exactly matches the same, latest version of the original package, its versions starting from **1.12.0** have all dependencies updated to their latest versions, and misc maintenance performed as needed. To migrate from the original [csurf] just replace all references to it by [@dr.pogodin/csurf]._

---

## Content
- [CSRF Demystified]
- [Installation]
- [API]
- [Examples]
  - [Simple ExpressJS Example]
    - [Using AJAX]
    - [Single Page Application (SPA)]
  - [Ignoring Routes]
  - [Custom Error Handling]

## CSRF Demystified
[CSRF Demystified]: #csrf-demystified

**Crux of [the problem][owasp-csrf]** &mdash; if browser knows an authentication
cookie for your domain, it will send it along with all HTTP(S) requests to your
domain,<sup>[&dagger;](#remark-01)</sup> even with those triggered automatically
by completely unrelated websites; thus allowing malicious third parties to make
authenticated requests to your API on behalf of the user, if he has loaded
their code by his browser.

<sup id="remark-01">&dagger;</sup> It will be so if you have opted for
[`SameSite=None`] for that cookie, or your user uses an outdated, or weird
browser, as up until recently [`SameSite=None`] was the default cookie setting
(_e.g._ [Chrome changed it to `SameSite=Lax` in 2020](https://developers.google.com/search/blog/2020/01/get-ready-for-new-samesitenone-secure)).
Naturally, people who select such defaults as [`SameSite=None`] have since moved
to senior positions, and now make six numbers teaching you about security, while
you fall into the pitfalls they created, not expecting that anybody sane would
design such default behaviors.

**[Three main ways to protect against CSRF][owsap-csrf-cheatsheet]**,
implemented by this library, in the nutshell all verify that the initiator of
HTTP(S) request is a part (legit or not) of your website running in the user's
browser. Mind, although we keep saying HTTP(S), we actually mean that you only
use HTTPS &mdash; if you are careless to permit unsecure HTTP connection to your
backend, why would you care about CSRF at all?

- [Synchronizer Token Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern)
  approach consists of the server generating a random token for the user session,
  and passing it to the user as a part of the HTML page (not _via_ a cookie, not
  serving it _via_ a dedicated GET endpoint &mdash; these options would make
  this approach useless). Every subsequent request to the server within that
  session is expected to read that token from the page, and pass it along with
  the request, thus proving that the request initiator is a part of the page
  served to that user within the current session (as guessing the token value
  would be problematic). Sure, a malicious code injected inside your page ([XSS])
  would be able to do the same, and thus pass your CSRF protection, but if you
  allow such injections, with or without CSRF protection you are fucked.

  This mode of CSRF protection is provided by this library when no
  ["cookie" option](#cookie) is set. It is also implemented somewhat smarter,
  as instead of remembering on server side the actual tokens issued to the user,
  it instead generates and remembers a cryptographic secret for that user and
  session, then uses it to generate random, signed tokens, and to later verify
  tokens passed to the server with user requests.

- 




## Installation
[Installation]: #installation

Requires either a session middleware or [cookie-parser](https://www.npmjs.com/package/cookie-parser) to be initialized first.

  * If you are setting the ["cookie" option](#cookie) to a non-`false` value,
    then you must use [cookie-parser](https://www.npmjs.com/package/cookie-parser)
    before this module.
  * Otherwise, you must use a session middleware before this module. For example:
    - [express-session](https://www.npmjs.com/package/express-session)
    - [cookie-session](https://www.npmjs.com/package/cookie-session)

If you have questions on how this module is implemented, please read
[Understanding CSRF](https://github.com/pillarjs/understanding-csrf).

This is a [Node.js](https://nodejs.org/en/) module available through the
[npm registry](https://www.npmjs.com/). Installation is done using the
[`npm install` command](https://docs.npmjs.com/getting-started/installing-npm-packages-locally):

```shell
$ npm install --save @dr.pogodin/csurf
```

## API
[API]: #api

<!-- eslint-disable no-unused-vars -->

```js
import csurf from '@dr.pogodin/csurf';
```

### csurf([options])

Create a middleware for CSRF token creation and validation. This middleware
adds a `req.csrfToken()` function to make a token which should be added to
requests which mutate state, within a hidden form field, query-string etc.
This token is validated against the visitor's session or csrf cookie.

#### Options

The `csurf` function takes an optional `options` object that may contain
any of the following keys:

##### cookie

Determines if the token secret for the user should be stored in a cookie
or in `req.session`. Storing the token secret in a cookie implements
the [double submit cookie pattern][owsap-csrf-double-submit].
Defaults to `false`.

When set to `true` (or an object of options for the cookie), then the module
changes behavior and no longer uses `req.session`. This means you _are no
longer required to use a session middleware_. Instead, you do need to use the
[cookie-parser](https://www.npmjs.com/package/cookie-parser) middleware in
your app before this middleware.

When set to an object, cookie storage of the secret is enabled and the
object contains options for this functionality (when set to `true`, the
defaults for the options are used). The options may contain any of the
following keys:

  - `key` - the name of the cookie to use to store the token secret
    (defaults to `'_csrf'`).
  - `path` - the path of the cookie (defaults to `'/'`).
  - `signed` - indicates if the cookie should be signed (defaults to `false`).
  - `secure` - marks the cookie to be used with HTTPS only (defaults to
    `false`).
  - `maxAge` - the number of seconds after which the cookie will expire
    (defaults to session length).
  - `httpOnly` - flags the cookie to be accessible only by the web server
    (defaults to `false`).
  - `sameSite` - sets the same site policy for the cookie(defaults to
    `false`). This can be set to `'strict'`, `'lax'`, `'none'`, or `true`
    (which maps to `'strict'`).
  - `domain` - sets the domain the cookie is valid on(defaults to current
    domain).

##### ignoreMethods

An array of the methods for which CSRF token checking will disabled.
Defaults to `['GET', 'HEAD', 'OPTIONS']`.

##### sessionKey

Determines what property ("key") on `req` the session object is located.
Defaults to `'session'` (i.e. looks at `req.session`). The CSRF secret
from this library is stored and read as `req[sessionKey].csrfSecret`.

If the ["cookie" option](#cookie) is not `false`, then this option does
nothing.

##### value

Provide a function that the middleware will invoke to read the token from
the request for validation. The function is called as `value(req)` and is
expected to return the token as a string.

The default value is a function that reads the token from the following
locations, in order:

  - `req.body._csrf` - typically generated by the `body-parser` module.
  - `req.query._csrf` - a built-in from Express.js to read from the URL
    query string.
  - `req.headers['csrf-token']` - the `CSRF-Token` HTTP request header.
  - `req.headers['xsrf-token']` - the `XSRF-Token` HTTP request header.
  - `req.headers['x-csrf-token']` - the `X-CSRF-Token` HTTP request header.
  - `req.headers['x-xsrf-token']` - the `X-XSRF-Token` HTTP request header.

## Examples
[Examples]: #examples

### Simple ExpressJS Example
[Simple ExpressJS Example]: #simple-expressjs-example

The following is an example of some server-side code that generates a form
that requires a CSRF token to post back.

```js
import cookieParser from 'cookie-parser';
import csrf from '@dr.pogodin/csurf';
import bodyParser from 'body-parser';
import express from 'express';

// setup route middlewares
const csrfProtection = csrf({ cookie: true })
const parseForm = bodyParser.urlencoded({ extended: false })

// create express app
const app = express()

// parse cookies
// we need this because "cookie" is true in csrfProtection
app.use(cookieParser())

app.get('/form', csrfProtection, function (req, res) {
  // pass the csrfToken to the view
  res.render('send', { csrfToken: req.csrfToken() })
})

app.post('/process', parseForm, csrfProtection, function (req, res) {
  res.send('data is being processed')
})
```

Inside the view (depending on your template language; handlebars-style
is demonstrated here), set the `csrfToken` value as the value of a hidden
input field named `_csrf`:

```html
<form action="/process" method="POST">
  <input type="hidden" name="_csrf" value="{{csrfToken}}">
  
  Favorite color: <input type="text" name="favoriteColor">
  <button type="submit">Submit</button>
</form>
```

#### Using AJAX
[Using AJAX]: #using-ajax

When accessing protected routes via ajax both the csrf token will need to be
passed in the request. Typically this is done using a request header, as adding
a request header can typically be done at a central location easily without
payload modification.

The CSRF token is obtained from the `req.csrfToken()` call on the server-side.
This token needs to be exposed to the client-side, typically by including it in
the initial page content. One possibility is to store it in an HTML `<meta>` tag,
where value can then be retrieved at the time of the request by JavaScript.

The following can be included in your view (handlebar example below), where the
`csrfToken` value came from `req.csrfToken()`:

```html
<meta name="csrf-token" content="{{csrfToken}}">
```

The following is an example of using the
[Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) to post
to the `/process` route with the CSRF token from the `<meta>` tag on the page:

<!-- eslint-env browser -->

```js
// Read the CSRF token from the <meta> tag
var token = document.querySelector('meta[name="csrf-token"]').getAttribute('content')

// Make a request using the Fetch API
fetch('/process', {
  credentials: 'same-origin', // <-- includes cookies in the request
  headers: {
    'CSRF-Token': token // <-- is the csrf token as a header
  },
  method: 'POST',
  body: {
    favoriteColor: 'blue'
  }
})
```

#### Single Page Application (SPA)
[Single Page Application (SPA)]: #single-page-application-spa

Many SPA frameworks like Angular have CSRF support built in automatically.
Typically they will reflect the value from a specific cookie, like
`XSRF-TOKEN` (which is the case for Angular).

To take advantage of this, set the value from `req.csrfToken()` in the cookie
used by the SPA framework. This is only necessary to do on the route that
renders the page (where `res.render` or `res.sendFile` is called in Express,
for example).

The following is an example for Express of a typical SPA response:

<!-- eslint-disable no-undef -->

```js
app.all('*', function (req, res) {
  res.cookie('XSRF-TOKEN', req.csrfToken())
  res.render('index')
})
```

### Ignoring Routes
[Ignoring Routes]: #ignoring-routes

**Note** CSRF checks should only be disabled for requests that you expect to
come from outside of your website. Do not disable CSRF checks for requests
that you expect to only come from your website. An existing session, even if
it belongs to an authenticated user, is not enough to protect against CSRF
attacks.

The following is an example of how to order your routes so that certain endpoints
do not check for a valid CSRF token.

```js
import cookieParser from 'cookie-parser';
import csrf from '@dr.pogodin/csurf';
import bodyParser from 'body-parser';
import express from 'express';

// create express app
const app = express()

// create api router
const api = createApiRouter()

// mount api before csrf is appended to the app stack
app.use('/api', api)

// now add csrf and other middlewares, after the "/api" was mounted
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(csrf({ cookie: true }))

app.get('/form', function (req, res) {
  // pass the csrfToken to the view
  res.render('send', { csrfToken: req.csrfToken() })
})

app.post('/process', function (req, res) {
  res.send('csrf was required to get here')
})

function createApiRouter () {
  const router = new express.Router()

  router.post('/getProfile', function (req, res) {
    res.send('no csrf to get here')
  })

  return router
}
```

### Custom Error Handling
[Custom Error Handling]: #custom-error-handling

When the CSRF token validation fails, an error is thrown that has
`err.code === 'EBADCSRFTOKEN'`. This can be used to display custom
error messages.

```js
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import csrf from '@dr.pogodin/csurf';
import express from 'express';

const app = express()
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(csrf({ cookie: true }))

// error handler
app.use(function (err, req, res, next) {
  if (err.code !== 'EBADCSRFTOKEN') return next(err)

  // handle CSRF token errors here
  res.status(403)
  res.send('form tampered with')
})
```

<!-- References -->

[@dr.pogodin/csurf]: https://www.npmjs.com/package/@dr.pogodin/csurf
[csurf]: https://www.npmjs.com/package/csurf
[ExpressJS]: https://expressjs.com
[owasp-csrf]: https://owasp.org/www-community/attacks/csrf
[owsap-csrf-cheatsheet]: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
[owsap-csrf-double-submit]: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie
[`SameSite=None`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value
[wikipedia-csrf]: https://en.wikipedia.org/wiki/Cross-site_request_forgery
[XSS]: https://owasp.org/www-community/attacks/xss
