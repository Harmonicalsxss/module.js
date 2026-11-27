# Audit: ro.place `main.339e40a9.js` (client bundle, from Safari.pdf)

Scope and limits
- Static review of a minified production bundle (about 4MB, about 1.4MB app code). Nothing was run or sent to the live site.
- Read in full: app entry/router, GraphQL operations (module 2350), purchase flow, login/forgot-password, seller-account (Roblox cookie) dialogs and reducer, all `message` listeners, all `window.open` / `location.href` / storage calls in app code.
- Not read line by line: remaining page components and all third-party libraries.
- Client code cannot prove server-side flaws. Items marked VERIFY-SERVER need a check on the API.
- Source maps are not available here, so fixes are written against the likely source. Apply them in the original repo, not the bundle.
- If this is not your site, send these to its owner privately instead of testing anything live.

## Security findings

| # | Severity | Finding |
|---|----------|---------|
| S1 | High (design) | Roblox account secrets sent to the server: username + password (`retrieveAccountCookie`), the `.ROBLOSECURITY` cookie (`addAccountCookie` / `updateAccountCookie`), and the Roblox 2FA setup key (`twoFactorKey`). The cookie is also returned to the browser in `accountData{cookie proxy}`. |
| S2 | High (design) | Sellers paste live payment secrets into the page: Stripe `sk_live_…` (`enableStripe`, `enableStripeCheckout`), PayPal client secret (`enablePaypal`), VersatilePay API key. |
| S3 | High, VERIFY-SERVER | State-changing and money-moving operations are declared as GraphQL `query`: `itemPurchase`, `initiateFundsPurchase`, `createDeposit`, `createItemCryptoPurchase`, `retrieveAccountCookie`, `completeLogin2FA`. The client uses `credentials:"include"` with no CSRF header. If the API accepts GET queries, they are CSRF-able. |
| S4 | High, VERIFY-SERVER | Client sends identity and price fields: `customerId`, `userId`, `amount`, `accountId`. The server must derive identity from the session and recompute prices and fees. Fee constants are also shipped in the bundle (`REACT_APP_SERVICE_FEE…`), so check the server never reads them from the request. |
| S5 | Medium | Server-supplied URLs are navigated to without checking scheme or host: `window.location.href = redirectUrl` (PayPal, Stripe Checkout, VersatilePay, Whop, Versatile), `window.open(redirectUrl)`, and `<iframe src={redirectUrl}>` for Stripe 3DS. A `javascript:` or attacker URL from a compromised API or MITM becomes XSS or phishing. |
| S6 | Medium | Stripe 3DS `message` listener (`ze`) never checks `event.origin` or `event.source`. It accepts any window's message that carries the right `paymentIntentId`, and it uses the message's `clientSecret`. Mitigated by server re-verification, but it should not rely on that. |
| S7 | Medium | Discord OAuth listener (`Lq`) reads `e.data.type` before checking origin, so a `null` payload throws. It has no `.catch`. |
| S8 | Medium | Admin-controlled banner and toast data (`link`, `secondLink`, `backgroundImgLink`) go straight into `href` and `img src`. A `javascript:` link in a banner is stored XSS if an admin account or the banner source is compromised. |
| S9 | Medium | `/item/success`, `/funds/success`, `/toy-codes` success UI is driven only by the URL (`?value=`, `?paymentMethod=`). Anyone can link a victim to a page that says "Purchase successful. A trade has been sent." The same `value` is sent to Google Ads as a conversion value (`gtag conversion`), so it is attacker-settable and pollutes conversion data. |
| S10 | Low-Med | Logout is `window.open("https://api.ro.place/logout")`, a GET in a popup. That is cross-site triggerable (forced logout) and can be popup-blocked. Local user state is not reset. |
| S11 | Low | `dialogTwoFactorKey` (the Roblox 2FA secret) is never cleared by `CLOSE_DIALOG`, so it stays in the reducer and can be re-sent with the next account added or updated. `twoFactorCode`/`ticket` are not cleared either. |
| S12 | Low | Forgot-password and login show the server's raw error message. If messages differ for unknown vs known users, that allows account enumeration (VERIFY-SERVER). |
| S13 | Info | Public-by-design identifiers are in the bundle (PayPal client ID, reCAPTCHA site keys, Sentry DSN, Evervault IDs, Castle `pk_`, Intercom app ID). Not leaks. Check the Sentry DSN has rate limits and allowed-domain rules. Route guards (`allowedAccountType`) are client-only, so the API must enforce them. |

## Bugs

| # | Where | Bug |
|---|-------|-----|
| B1 | `JM` GlobalStyles | `"".concat(fn, "!important")` stringifies a function, so body background and colour CSS is invalid and ignored. |
| B2 | `Lq` | `e.data.type` throws on non-object messages. |
| B3 | `bM` refund | `n.graphQLErrors[0].extensions.code` throws on network errors. Errors shown with `toast.info`. |
| B4 | `NM` | `setState` inside `useMemo`, and stale `itemId` in `k` (not in deps). |
| B5 | checkout | `window.open` after `await` is blocked by Safari. The Versatile error text says "Whop". |
| B6 | storage | Unguarded `localStorage` / `sessionStorage` (theme provider, `user_data`, `sponsorCode`, `last_used_roblox_profile`, `pendingPurchaseValue`) throws in Safari with blocked site data. |
| B7 | `GM` | Intercom session cookie is expired on every load while the user is still `null`, with no path or domain. |
| B8 | `GM` | Reads `window.location.pathname` during render, so the route gate goes stale after client navigation. |
| B9 | `GM` | Maintenance and currency queries have no `.catch`. |
| B10 | purchase fn `C` | `sponsorCode` is removed from `localStorage` after the first attempt, so a 3DS retry loses affiliate attribution. `n.paymentIntent.status` and `s.next_action.type` are dereferenced unguarded. |
| B11 | payment method names | Case-sensitive branches `"PayPal"` vs `"Paypal"` and `"Versatile"` vs `"VersatilePay"` are fragile. A server rename silently falls through to no-op. |
| B12 | login catch | `e.graphQLErrors.length` throws if the error is not an ApolloError. |
| B13 | account dialog `F` | Destructures `t` after an error, so a failed request ends in the `catch` with a confusing message. |
| B14 | misc | `NM` hijacks Cmd/Ctrl+F site-wide. `exact` on RR v6 `<Route>` does nothing. Hard-coded `https://ro.place/` origins. Default sort uses a `value` field the query does not select. |

## Fixes

### S5 / B5: safe navigation for payment redirects
```js
// utils/safeRedirect.js
const ALLOWED_HOSTS = new Set([
  'checkout.stripe.com', 'hooks.stripe.com', 'www.paypal.com',
  // add the exact Whop / VersatilePay / Unlimit checkout hosts you use
]);
export function parseSafeUrl(raw) {
  try {
    const u = new URL(raw, window.location.origin);
    if (u.protocol !== 'https:') return null;
    const ok = u.origin === window.location.origin || ALLOWED_HOSTS.has(u.hostname);
    return ok ? u.href : null;
  } catch { return null; }
}
export function goTo(raw) {
  const href = parseSafeUrl(raw);
  if (!href) throw new Error('Unexpected payment redirect.');
  window.location.assign(href);          // same tab: not blocked by Safari
}
// replace every `window.location.href = redirectUrl` and
// `window.open(redirectUrl, '_blank')` with goTo(redirectUrl)
// iframe: <iframe src={parseSafeUrl(redirectUrl) ?? 'about:blank'}
//          sandbox="allow-scripts allow-forms allow-same-origin" referrerPolicy="no-referrer" />
```

### S6: Stripe 3DS listener
```js
const onMessage = (ev) => {
  if (ev.origin !== window.location.origin) return;           // or the exact return-page origin
  if (ev.source !== iframeRef.current?.contentWindow) return;
  const msg = parseJsonSafe(ev.data);
  if (msg?.name !== '3DS-authentication-complete' || msg.paymentIntentId !== expectedIntent.current) return;
  // do not use msg.clientSecret: keep the clientSecret you already hold from the purchase response
  ...
};
```

### S7 / B2: Discord listener
```js
const onMessage = (e) => {
  if (e.origin !== window.location.origin) return;
  if (e.data?.type !== 'discordAuth' || typeof e.data.code !== 'string') return;
  exchange({ variables: { code: e.data.code } })
    .then(r => { result.current = r.data.getDiscordOAuthData.token; })
    .catch(() => toast.error('Discord authorization failed'));
};
```

### S8: banner and toast links
```js
const safeHref = (u) => /^https?:\/\//i.test(u) ? u : undefined;   // blocks javascript:, data:
// <a href={safeHref(e.link)} target="_blank" rel="noopener noreferrer">
// <img src={safeHref(b.backgroundImgLink)} alt="" />
```
Also add a `Content-Security-Policy` (no `unsafe-inline` for scripts, `frame-src` limited to Stripe, Whop, Coinbase, and so on, `object-src 'none'`, `base-uri 'none'`).

### S9: success page
```js
// Do not render success from the URL. Confirm with the server:
const { data } = useQuery(PURCHASE_STATUS, { variables: { purchaseId } });   // owner-scoped on the server
if (data?.purchaseStatus.state === 'paid') {
  gtag('event', 'conversion', { send_to: '…', value: data.purchaseStatus.usdValue, currency: 'USD' });
}
```

### S10: logout
```js
const logout = async () => {
  await fetch(`${API}/logout`, { method: 'POST', credentials: 'include', headers: { 'x-csrf': token } });
  apolloClient.clearStore();
  dispatch({ type: 'SET_USER', payload: false });
  navigate('/login', { replace: true });
};
```
Server: make `/logout` POST-only.

### S11: clear secrets
```js
case 'CLOSE_DIALOG':
  return { ...initial.dialog, dialogFormOpen: false, dialogTwoFactorKey: '', twoFactorCode: '',
           twoFactorTicket: '', twoFactorUserId: 0, captchaToken: '', captchaTicket: '' };
```
Clear the same fields after a successful add or update.

### S3 / S4 (server and client)
- Server: reject GET for any operation containing a mutation or a money-moving resolver. Require a custom header (for example `apollo-require-preflight`) or a CSRF token. Set `SameSite=Lax` or `Strict` and `HttpOnly; Secure` on the session cookie. Use a strict CORS allow-list with credentials.
- Client: change those `query` declarations to `mutation` and use `useMutation`.
- Server: ignore `customerId`, `userId` and `accountId` from the client for authorization. Resolve the user from the session, and check ownership of every `accountId`, `itemId` and `purchaseToken`. Recompute amounts and fees on the server. Rate-limit `canPurchase`, `fetchFundsSeller`, `createDeposit`.

### S1 / S2: secrets
- Roblox: do not collect passwords and 2FA seeds. If cookie-based access is unavoidable, accept only the cookie, never return it to the browser, store it encrypted server-side, and tell sellers plainly what the cookie can do.
- Payments: accept restricted Stripe keys only (`rk_live_…`, minimal scopes), reject `sk_live_…`. Prefer OAuth (Stripe Connect, PayPal Commerce Platform) so sellers never paste secrets.

### B1: GlobalStyles
```js
<GlobalStyles styles={(theme) => ({
  html: { backgroundColor: `${theme.body} !important`, color: theme.mainTextColor },
  body: { backgroundColor: `${theme.body} !important`, color: theme.mainTextColor },
})} />
```

### B3 / B12: error handling
```js
const code = err?.graphQLErrors?.[0]?.extensions?.code;
toast.error(err?.message ?? 'Something went wrong');
if (code === 'DUPLICATE_TICKET') navigate('/roblox-toy-codes', { replace: true });
```

### B4: explorer
```js
const grouped = useMemo(() => groupItems(...), [...]);          // pure
const rows = grouped.items.map(item => <Row key={item.itemId} onClick={() => handleClick(item)} />);
// handleClick created with useCallback([itemId, navigate, ...]); no setState inside useMemo
```

### B6: storage
```js
const store = {
  get: (k) => { try { return localStorage.getItem(k); } catch { return mem.get(k) ?? null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch { mem.set(k, v); } },
  remove: (k) => { try { localStorage.removeItem(k); } catch { mem.delete(k); } },
};
const mem = new Map();
```
Use it everywhere, including the theme `useState` initialiser.

### B7: Intercom
```js
useEffect(() => {
  if (loading) return;                     // wait until the user query resolves
  if (user) update({ email: user.email, userHash: user.intercomHmac });
  else shutdown();                         // Intercom's own API, not document.cookie
}, [user, loading]);
```

### B8: route gate
```js
const { pathname } = useLocation();        // inside the Router, so it updates on navigation
const hasSeenApp = useSyncExternalStore(subscribeStorage, () => store.get('user_data'));
```

### B9 / B13: add `.catch` handlers
```js
maintenance({ fetchPolicy: 'no-cache' }).then(…).catch(() => setMaintenance(false));
currency({ fetchPolicy: 'no-cache' }).then(…).catch(() => {});
```

### B10: purchase function
- Remove `sponsorCode` only after the purchase reaches a terminal state (success or hard failure), not on the first response.
- Guard: `n.paymentIntent?.status`, `s.next_action?.type`.
- Use one shared constants map for method names, not string literals.

## Addendum: `index.html` shell (static review of the served HTML)

The shell references `/static/js/main.339e40a9.js`, the bundle reviewed above, so S1-S13 and B1-B14 apply to it.
Response headers were not provided. CSP, HSTS, `X-Frame-Options` and cookie flags need a check on the live response (`curl -sI https://ro.place/`).

| # | Severity | Finding |
|---|----------|---------|
| H1 | Medium | No Content-Security-Policy in the HTML (no `<meta http-equiv>`). Combined with S5 and S8, any injected script or `javascript:` link runs with full page privileges. The page needs a header-based CSP. The inline gtag script needs a hash or nonce. |
| H2 | Medium | Third-party scripts run with full page access and no Subresource Integrity: Trustpilot `//widget.trustpilot.com/bootstrap/v5/tp.widget.bootstrap.min.js` and `googletagmanager.com/gtag/js`. Trustpilot's file is unversioned, so a compromise on their side runs on a page that handles logins, Roblox cookies and payments. Own-origin `main.*.js` also has no `integrity`. Consider loading Trustpilot only on marketing pages, not on checkout or seller-account routes. |
| H3 | Low | The Trustpilot URL is protocol-relative (`//`). Use `https://` explicitly. `type="text/javascript"` is redundant. |
| H4 | Low-Med (privacy/legal) | `gtag("config", ...)` for Analytics and Google Ads (`AW-11295142200`) runs unconditionally on load, before any consent step. That is an ePrivacy/GDPR problem for EU and UK visitors. Use Consent Mode v2 (`gtag('consent','default',{ad_storage:'denied',analytics_storage:'denied',ad_user_data:'denied',ad_personalization:'denied'})`) before the config calls. Combined with S9, the conversion value is also URL-controlled. |
| H5 | Info | No `<link rel="canonical">`. Hashed assets without a Cache-Control `immutable` header are not visible from here. |

| # | Where | Bug |
|---|-------|-----|
| H6 | `og:image` | The value is relative (`/favicon.png`). Facebook, X, Discord and Slack require an absolute URL and usually show no preview. Use `https://ro.place/og-image.png` (1200x630) and add `og:image:width/height` and `twitter:card`. |
| H7 | og tags | `og:url`, title and description are fixed for the whole SPA. Every route (item pages, toy codes) shares one preview, and crawlers that do not run JS see an empty `<div id="root">`. Per-route meta needs prerendering, SSR or a prerender service. |
| H8 | `<noscript>` | Only a plain message. No crawlable fallback content. |

Second capture of the shell (with a trailing inline script): the extra block is Cloudflare's bot-detection snippet (`/cdn-cgi/challenge-platform/scripts/jsd/main.js`, `__CF$cv$params`), injected at the edge. It is normal, not a finding. It does show:
- The site is behind Cloudflare, so security headers and CSP can be set there (Transform Rules) as well as at the origin.
- A CSP must allow this injected inline script and `/cdn-cgi/` on the same origin. A nonce does not work on edge-injected code, so use a hash, or `script-src 'self'` plus the iframe-created script, which is same-origin. Test in report-only mode first.
- The snippet reads `window.parent.location` from a hidden same-origin iframe. Do not add `X-Frame-Options`/`frame-ancestors` rules that would break that iframe (it is same-origin, so `frame-ancestors 'self'` is safe, `'none'` is also fine for external framing).
- Because the origin is behind Cloudflare, check the origin IP is not directly reachable (firewall to Cloudflare ranges), or WAF and rate limits can be bypassed.

Suggested CSP starting point (tune after a report-only run):
```
Content-Security-Policy-Report-Only:
  default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';
  script-src 'self' 'sha256-<gtag inline hash>' https://www.googletagmanager.com https://widget.trustpilot.com <recaptcha/stripe/intercom hosts>;
  connect-src 'self' https://api.ro.place <sentry, analytics hosts>;
  frame-src https://js.stripe.com https://hooks.stripe.com <whop/coinbase/recaptcha>;
  img-src 'self' data: https:;
```
Also set `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy`.

## Suggested order of work
1. S3 and S4 on the server (CSRF, GET-queries, authz). These are the most likely to cause real loss.
2. S5, S6, S7, S8 (about an hour of client work plus a CSP).
3. S1 and S2 (product decisions).
4. B6, B1, B3, B7 (visible Safari and UX breakage).
5. The rest.
