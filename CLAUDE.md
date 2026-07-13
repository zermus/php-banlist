# CLAUDE.md — php-banlist

Operational context for working in this repo. Read before proposing changes.
The invariants below are load-bearing and several are *settled decisions* — do
not reopen them without an explicit ask.

## What this is

Self-hosted PHP/MariaDB firewall ban-list manager. Maintains IP and FQDN ban
lists, serves them as plain `.txt` feeds a firewall can pull, and exposes a
small write API. MIT licensed. Author: Cody Gee.

Target/dev environment: PHP 8.0+ (dev box is 8.3), MariaDB/MySQL, Apache with
`AllowOverride All`, self-hosted Linux. Deployed via a versioned-symlink flip.

## The no-JS posture (most important invariant)

**The UI ships zero JavaScript by default, and this is enforced — not just a
style preference.** `private/header.php` sends a hard CSP on every page:

```
default-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';
img-src 'self' data:; style-src 'self'; font-src 'self'; connect-src 'self';
```

There is **no `script-src`**, so it falls back to `default-src 'none'` → no
script executes, inline or external. There is **no `'unsafe-inline'`**, so
inline `style="..."` attributes and inline `onsubmit=`/`on*=` handlers are
silently dead too. `style-src 'self'` permits only the served
`assets/style.css`.

Consequences to internalize:
- All interactivity is server round-trips (GET/POST + redirects), never JS.
- Every visual style goes in `assets/style.css`. Never an inline `style=` attr.
- Never write an inline event handler or `<script>` block.
- **If JS is ever genuinely required** (not currently): it must be a served
  file under `assets/` (or similar) allowed via `script-src 'self'`. Never
  `unsafe-inline`, never inline. This has not been needed; pagination, confirms,
  and duration-picking are all solved JS-free.

### Recurring bug class — audit every release
Inline code that the CSP silently kills. This has bitten the project at least
three times since v0.1: a dead `onsubmit="confirm(...)"` handler, and inline
`style=` attributes (most recently on `profile.php` in v0.4). Symptom: it
"works" with CSP disabled and does nothing with it on. Before packaging a
release, grep the tree for `onsubmit=`, ` on*=` handlers, `style=` attributes,
and `<script`, and confirm none exist.

## Destructive actions: JS-free confirm interstitial

Never a JS `confirm()`. The established pattern (see `ip-bans.php`,
`fqdn-bans.php`, `profile.php`, `tokens.php`, `users.php`):

1. Row action is a **GET** link built by `confirm_link($action, $id)`.
2. That GET is caught by `confirm_request([...])`, which renders an
   interstitial page via `confirm_card($post_url, $prompt_html, $action, $id,
   $verb)`.
3. The card's confirm button submits a **POST** (with `csrf_field()`) that
   performs the mutation, then redirects back with `list_state_qs()` preserving
   filter/page state.

Use this pattern for any new destructive action. Do not shortcut it.

## Two auth models — keep them separate

**UI (session-based, CSRF-protected).** Browser pages authenticate via session
cookie. Every mutating POST calls `csrf_check()` and every form emits
`csrf_field()`. Roles gate writes: `role_can_write($u)`,
`role_can_admin_users($u)`.

**Write API (`api.php`) — token only, sessions/cookies NEVER consulted.** This
is deliberate and load-bearing: because no cookie is ever read, a logged-in
browser cannot be made to drive the endpoint cross-site, so **CSRF does not
apply** and the API needs no CSRF token. Do not add session/cookie lookups to
`api.php` — doing so would reintroduce the CSRF surface the design removes.

`api.php` specifics:
- **POST only.** Form-encoded or JSON body. 405 otherwise.
- **Double-gated:** the `enable_write_api` setting (global, superadmin) AND the
  token's `can_write` flag must both be on. Existing feed tokens stay read-only
  until explicitly upgraded.
- Auth via `X-API-Token` header (preferred; keeps secret out of access logs) or
  `token=` param. Token hashed with sha256 for the DB lookup.
- Scope enforced: token `list_type` of `ip`/`fqdn`/`both` must cover the request
  `type`.
- Optional `api_acl` (CIDR) source-IP restriction, separate from the feed ACL.
- All writes audit-logged with actor `token:<label>`; bans attributed to the
  token's `created_by` user (NOT NULL FK).

## Config split: `config.php` vs `settings` table

Two homes for configuration, on purpose. Put new config in the right one.

**`config.php`** (file; copied from `config.example.php`; git-ignored) — for
anything read on the unauthenticated bootstrap path or that must be a hard floor
a compromised UI session cannot loosen:
- `remember_me` (enabled/days/cookie) — consulted before auth on the login path.
- `login_protection` per-IP brute-force floor (`per_ip_max_attempts`,
  `per_ip_window_min`) — a hard floor; `login_policy()` merges it with the
  UI-tunable per-account thresholds.
- `db`, `passwords` policy, `retention`, `trusted_proxies`, `list_acl`,
  `api_acl`, `site`, `session` (absolute_ttl, regen_every).

**`settings` table** (UI-tunable via `settings.php`; read with `setting(key,
default)`, written with `setting_set()`) — operational knobs safe to change from
an admin session: `session_timeout_minutes` (idle), `max_failed_logins`,
`lockout_minutes`, `default_timeout_seconds`, `default_timezone`,
`enable_write_api`, `require_token_for_lists`.

Rule of thumb: bootstrap-path or security-floor → `config.php`. Day-to-day
operational knob → settings table.

## Settled decisions — do not reopen without an explicit ask

- **Per-feed token-gating was rejected.** IP and FQDN feeds leak equivalent
  intelligence, so requiring a token for one but not the other is false
  security. The `require_token_for_lists` toggle covers both feeds together.
  (Per-token `ip`/`fqdn`/`both` scoping is still valuable for credential
  hygiene and stays.)
- **Per-IP brute-force floor stays in `config.php`**, not UI-tunable.
- **Remember-me config stays in `config.php`**, not the settings table (bootstrap
  path).
- **Asymmetry between self-service password change and admin reset is
  intentional:** self-service change revokes *other* devices' remember tokens
  but spares the current device; admin reset of another user revokes *all* of
  that user's tokens (spares none).

## Layout & structure

- `private/` — server-side includes only; its `.htaccess` denies all HTTP
  access. `auth.php`, `db.php`, `functions.php`, `header.php`, `footer.php`.
- `assets/` — `style.css`; its `.htaccess` denies PHP execution (defense in
  depth).
- Feeds: `list.php?type=ip|fqdn`, exposed as clean URLs `IP-list.txt` /
  `FQDN-list.txt` via root `.htaccess` rewrites. Optional `list_acl` +
  `require_token_for_lists`.
- `cron/expire.php` — nightly: removes expired bans, prunes rolling logs per
  `retention`, prunes remember-me tokens at their own expiry. `cron/.htaccess`
  denies HTTP access.
- Root `.htaccess` blocks raw access to `config.php`, dotfiles, and source-ish
  extensions (`.sql`, `.example`, `.bak`, `.swp`, etc.).
- Pages: `index.php` (dash), `ip-bans.php`, `fqdn-bans.php`, `audit.php`,
  `users.php`, `settings.php`, `tokens.php`, `profile.php`, `login.php`,
  `logout.php`, `api.php`.

## Schema & migrations

- `sql/migrations/` holds an ordered chain: `0001-initial.sql`,
  `0002-v0.3.sql`, `0003-v0.4.sql`. Keep it intact; migrations are additive.
- Applied automatically by `install.php` (`ensure_migrations_table()` +
  `run_pending_migrations()`), tracked in a migrations table. Do not run by
  hand.
- A new release that changes schema adds the next `000N-vX.Y.sql`; note in the
  upgrade path whether `install.php` must be re-run.

## Dev workflow

- Versioned release cycles. Each cycle ends with a `php-banlist-vX.Y-scope.md`
  planning artifact that seeds the next (this is a working doc, not shipped in
  the release tarball).
- End-to-end smoke tests against a **real MariaDB** validate migrations, logic,
  and the security gates before packaging.
- Package as a tarball; deploy by unpacking a new versioned dir and flipping the
  symlink. Upgrade notes state whether `install.php` re-run / migrations apply.
- Editor is vim. Work happens in intermittent bursts, not daily.

## Current state / next

- **v0.4 shipped.** Added: JS-free pagination (ip/fqdn/audit, 100 rows/page,
  state preserved across confirm round-trips and redirects, out-of-range clamps
  to last page); the write API (`api.php` + `0003` migration); remembered-devices
  UI on `profile.php` with per-device revocation; password-change/admin-reset
  token-revocation fixes; the `profile.php` inline-`style=` CSP fix.
- **v0.5 proposed theme: Nginx support** (currently Apache/`.htaccess` only).
  Note the many `.htaccess` protections above have no automatic Nginx
  equivalent — access control for `private/`, `cron/`, `config.php`, the feed
  rewrites, and the no-PHP-in-`assets/` rule would each need an Nginx
  translation.
