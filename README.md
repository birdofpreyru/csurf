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
cookie for your domain, it may send it along with all HTTP(S) requests to your
backend,<sup>[&dagger;](#remark-01)</sup> even with those triggered automatically
by completely unrelated websites; thus allowing a malicious third party to make
authenticated requests to your API on behalf of the user, if he has loaded their
page into his browser (_i.e._ a bad actor does not have to know those cookies,
it may just rely on the user's browser sending them automatically, directly to
your API).

<sup id="remark-01">&dagger;</sup> It happens if you have opted for this
([`SameSite=None`] &mdash; bad idea), or your user uses an outdated, weird
browser, as up until recently [`SameSite=None`] was the default cookie setting
(_e.g._ [Chrome changed it to `SameSite=Lax` only in 2020](https://developers.google.com/search/blog/2020/01/get-ready-for-new-samesitenone-secure)).
Naturally, people who selected such default behavior ([`SameSite=None`]) have
since moved to senior positions, and now make six numbers teaching you about
security, while you fall for the pitfalls they created (_i.e._ they selected
that default with tracking applications of third-party cookies in mind, and
they had not thought what does it mean for possible authentication applications
of cookies).

**[Three main ways to protect against CSRF][owsap-csrf-cheatsheet]**,
implemented by this library, in the nutshell all verify that the initiator of
HTTP(S) requests is a part (legit or not) of your website running in the user's
browser, _i.e._ it is actually able to read (or write) your cookies (as browser
only allows the frontend to access cookies from the same origin). Mind, speaking
of HTTP(S) requests we actually assume that you only use HTTPS &mdash; if you
are careless enough to permit unsecure HTTP connection to your backend,
why would you care about CSRF at all?

- [Synchronizer Token Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern)
  approach consists of the server generating a random token for the current user
  session, storing it at the server side, and also passing it to the frontend
  along with the HTML page. To make an API request the frontend is expected
  to read that token, and to pass it back to the server as a part of the request
  payload, or in its header. The server compares the token value received with
  the request to the value stored at the backend for that user session, and if
  they match it proves that the request initiator is a part of the page, able
  to read cookies set for that origin, or the actual HTML served for that user.
  Sure, a malicious code injected inside your page ([XSS]) will be able to do
  just the same, and thus to bypass your CSRF protection, however if you allow
  such injection, then there is no need to worry about CSRF protection &mdash;
  with or without it you are fucked.

  This mode of CSRF protection is provided by this library when no
  [`cookie` option](#cookie) is set. It is also implemented somewhat smarter,
  as instead of storing on the server side the actual tokens issued to the user,
  it instead generates, and stores a random cryptographic secret for that user
  session, and then uses it to generate random, signed tokens, and to later
  verify these tokens when they are passed back to the server with API requests.

- [Naive Double-Submit Cookie Pattern][owsap-naive-double-submit]
  approach consists of the server generating a random token for the current user
  session, and just passing it to the frontend _via_ cookie. To make an API
  request the frontend is expected to read that token, and to pass it back to
  the server as a part of the request payload, or in its header, while the browser
  also includes into the request the original cookie. The server compares these
  two token values (the one received in the cookie, with the one included into
  the request payload or header), and if they match it proves that the request
  initiator is a part of the page, able to read (or write) cookies set for that
  origin. Beside the danger of [XSS] defeating this protection; if a bad actor
  controls (or [XSS]'es) a sub-domain of protected domain, he will be able to
  defeat it, because he can overwrite the original cookie set by the server for
  protected domain, and thus bypass CSRF protection just by sending along with
  request his own pair of matching cookie (token) values.

  This mode of CSRF protection is provided by this library when
  the [`cookie` option](#cookie) is set `true`. It is also implemented somewhat
  differently, to reuse the same code and logic used for the previous mode &mdash;
  it generates a random secret for user session (though, it is not quite a secret,
  it does not have to be in this scenario), then it generates a matching random
  token, signed by that secret, and it sends them both to the frontend _via_
  two different cookies. To make requests, the frontend is expected to read
  the token from one of these cookies, and to include it into the request payload,
  or header. Upon receiving the request server verifies that the token received
  in the request payload (header) is signed by the secret received _via_
  the corresponding cookie. Once again, this check does not rely at all on that
  &laquo;secret&raquo; being secret, it just cares whether that &laquo;secret&raquo;
  and the token are a matching pair or not &mdash; it would provide the same
  protection if the frontend would just pass inside the request the &laquo;secret&raquo;
  value itself, to be directly compared to its value in the cookie.

- [Signed Double-Submit Cookie][owsap-csrf-double-submit]
  approach is essentially the same, but it requires the cookie with the token
  to be signed and verified on the server side. This way, even if a bad actor
  controls a sub-domain, and thus is able to overwrite the token cookie for
  the protected domain, it will be detected by the server.

  This mode of CSRF protection is provided by this library when
  the [`cookie` option](#cookie) is set to the object with cookie configuration
  enabling the signature (`signed` flag). Because of the way it is implemented
  (the token in request is verified against the &laquo;secret&raquo; stored in
  one of these cookies), it is actually necessary to sign and protect from
  modification of that &laquo;secret&raquo; cookie, to which that
  [`cookie` option](#cookie) is actually applied. Also, as the frontend
  does not really need to know that &laquo;secret&raquo; to send requests,
  it won't hurt to also opt for [`HttpOnly`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#httponly),
  `secure`, and other security options for that cookie, although it is not quite
  relevant for this mode of protection to work.

**The drama** around the claim of [csurf] library being vulnerable started with
[this article, &laquo;A CSRF Vulnerability in The Popular CSURF Package&raquo;](https://fortbridge.co.uk/research/a-csrf-vulnerability-in-the-popular-csurf-package).
The problem is that security &laquo;expert&raquo; who wrote it does not quite
understand neither CSRF protection, nor JavaScript, thus he just got confused
with the library implementation details, briefly explained above ¯\\\_(ツ)_/¯
Essentially, he argues that with the simple `cookie: true` setting the library
does not correctly implement [Signed Double-Submit Cookie][owsap-csrf-double-submit]
protection, as it does not sign the cookies it sets, it does not protect
the &laquo;secret&raquo; cookie, and it does not check the value of cookie with
token in subsequent API requests. Indeed, with that setting it correctly
implements a variant of [Naive Double-Submit Cookie][owsap-naive-double-submit]
protection, with its limitations not affecting most of simple websites.

That article ends with a misleading claim that library developers acknowledged
the bug, and deprecated the library because of it; while in reality the deprecation
note in GitHub repo read &laquo;_This npm module is currently deprecated due to
the large influx of security vulnerability reports received, most of which are
simply exploiting the underlying limitations of CSRF itself. The Express.js
project does not have the resources to put into this module, which is largely
unnecessary for modern SPA-based applications._&raquo; &mdash; essentially
saying &laquo;the library is fine, but we do not want to spend our time replying
to each idiot who complains about this library's vulnerabilities, without
understanding the matter&raquo;.

In reality, the most dangerous moment about it was that deprecation of
the original library, and re-telling of that article around Internet, encouraged
developers to switch from this, long-standing CSURF library to one of many new
CSRF-protection libraries written from scratch by different people (who don't
notice anything wrong about that article, thus guess their level of competence
in the subject). This both opens opportunities for dependency poisoning
(_i.e._ somebody creates a new CSRF-protection library with some malicious code
embedded in), or for honest mistakes (be sure, this long standing library had
more eyes revising its implementation than any of its new alternatives out there).
That's why this fork of the original CSURF came into existence &mdash; instead
of trying my luck with a new alternative, I just forked this time-proven library,
reviewed its code, just in case, updated dependencies, and converted the source
codebase to TypeScript (just for the ease of future maintenance). The project is
open-source, thus everybody is welcome to additionally review it and suggest any
improvements or fixes.

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
[owsap-csrf-double-submit]: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#signed-double-submit-cookie-recommended
[owsap-naive-double-submit]: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#naive-double-submit-cookie-pattern-discouraged
[`SameSite=None`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value
[wikipedia-csrf]: https://en.wikipedia.org/wiki/Cross-site_request_forgery
[XSS]: https://owasp.org/www-community/attacks/xss
