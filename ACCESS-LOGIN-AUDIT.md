# Audit: Cloudflare Access login page (pasted HTML/CSS/JS)

Scope and limits
- Static review of one pasted login page (a Cloudflare Access hosted page in front of a Grafana admin host, GitHub IdP plus email one-time PIN). Nothing was requested from or sent to the live site.
- Response headers, the Access policy and the Grafana origin config were not available. Items marked VERIFY need a check in the dashboard or on the origin.
- Host, tenant and token values are deliberately left out of this file.

## Security findings

| # | Severity | Finding |
|---|----------|---------|
| V1 | Medium, VERIFY | **Email one-time PIN is enabled next to GitHub SSO.** If the policy is broad (an email domain such as gmail.com, "Everyone", or a loose "emails ending in" rule), anyone who can receive mail at a matching address gets into an admin Grafana. Restrict OTP to an explicit email allow-list or remove it, and require the GitHub org/team via the IdP. |
| V2 | Medium, VERIFY | **Origin must not be reachable except through Access.** Confirm the Grafana origin rejects direct hits (tunnel or firewall to Cloudflare only) and validates `Cf-Access-Jwt-Assertion` (audience and signature) rather than trusting an email header. Check Grafana's own anonymous access and default admin credentials. |
| V3 | Low-Med | **Navigation sink without scheme check.** `window.location = url` where `url` comes from `data-auto-redirect-url`. When the fragment is empty, `withFragment` returns the value untouched, so a `javascript:` value would execute. Only exploitable if the server ever reflects user input into that attribute (VERIFY-SERVER), but the client should enforce `https:` and same-site or known hosts. The same applies to the `keyup` handler's `window.location = idp.getAttribute('href')`. |
| V4 | Low | **Fragment is carried through the IdP in `state`.** The user-controlled `#fragment` is base64-encoded into `state`/`RelayState` and later restored by the server. The server must treat it as untrusted: no reflection into HTML or redirect targets, strict length and charset. |
| V5 | Low | **CSP.** The page has two inline scripts and inline styles, so a CSP can only be nonce/hash-based or `unsafe-inline`. VERIFY headers: nonce or hash for scripts, `frame-ancestors 'none'` (clickjacking of the login page), `Referrer-Policy`, `X-Content-Type-Options`. |
| V6 | Low | **Remote logo from a custom CDN subdomain.** If that subdomain is ever taken over or its bucket becomes writable, the login page can be given a spoofed image (phishing text rendered in the "logo"). Keep the DNS and bucket locked down, or inline the logo. |
| V7 | Info | **Pasted markup contains live-looking values** (Access app AUD tag, IdP id, nonce, `state`, a signed `meta` JWT). The JWT lives 5 minutes, so it is expired by now, and none of these are credentials. Still avoid re-posting full login pages. The GitHub `client_id` is public by design. |

## Bugs

| # | Where | Bug |
|---|-------|-----|
| B1 | `withFragment` | `btoa(JSON.stringify(...))` throws on non-Latin1 characters. `location.hash` is normally percent-encoded so it rarely triggers, but an exception here aborts the whole `DOMContentLoaded` loop (remaining IdP links are not rewritten) and the auto-redirect. Use a UTF-8-safe encoder or try/catch. |
| B2 | `withFragment` | Silently drops the fragment when it is 100 characters or longer, or when the URL has neither `state` nor `RelayState`. The user lands on the app without their deep-link anchor, with no feedback. |
| B3 | `withFragment` | `new URL(url)` throws for a relative `data-auto-redirect-url`, which cancels the redirect. |
| B4 | `keyup` handler | Fires for Ctrl/Cmd/Alt+digit (browser tab switching) and navigates away. Ignore events with modifier keys. The link also has `accesskey="1"`, so the same shortcut is handled twice. |
| B5 | OTP form | Posts empty hidden `client_id`, `connector_id`, `connector_type`, `redirect_url` fields alongside a `redirect_url` in the action's query string. If the server prefers the body value, the deep link is lost after OTP login (VERIFY-SERVER). |
| B6 | Header link | `<a class="OrgAvatarLink" href="">` points at the current page (reloads it). Give it a real destination or make it non-interactive. |
| B7 | Logo `<img>` | No `alt`, no `width`/`height` (layout shift once it loads), and no `referrerpolicy`. The inline script waits for `load` only, so an `error` leaves a blank logo box with the title still rendered. |
| B8 | Email input | `autocomplete="off"` on a login email blocks autofill and password managers. Use `autocomplete="email"` (or `username`). |
| B9 | Logo SVG | Every path is hard-coded `fill="white"`. On any light theme or light card background the Cloudflare mark is invisible. Use `currentColor` or theme tokens. |
| B10 | CSS | `.PasskeyManagement .passkeys-actions` is declared twice with conflicting `gap` (the later `var(--spacing)` wins over the earlier `* 2`). `.passkeys-meta span { white-space: nowrap }` can overflow narrow screens when values are long. The pasted block also starts with a stray `}`, so the paste is truncated mid-rule. |
