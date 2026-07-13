php-banlist
===========

Version 0.5. Self-hosted manager for dynamic firewall banlists.
Two feed URLs (rewritten by the web server to list.php):

  <base>/IP-list.txt    one IPv4/IPv6 address or CIDR per line
  <base>/FQDN-list.txt  one hostname per line

Generated on every request from the database. No static files on disk
(you won't see them in `ls`). Plain-text, one entry per line, #
comment header, UTF-8 - the universal format any URL-driven firewall
accepts.


REQUIREMENTS
------------

  - Apache 2.4 with mod_rewrite (mod_headers, mod_expires recommended),
    or Nginx with php-fpm (new in 0.5; see nginx.conf.example)
  - PHP 8.0+ (tested on 8.3)
  - MariaDB 10.6+ or MySQL 8.0+
  - PHP extensions: pdo, pdo_mysql, session, mbstring, openssl,
    filter, hash


FEATURES
--------

  - Three roles: readonly, admin, superadmin
  - Per-entry expiry with calendar-accurate durations:
    s/m/h/d/w/mo/y/p (seconds through years, p = permanent)
  - Per-user timezone (US, Europe, Russia, Japan, India, Australia
    presets); UTC stored, local-time displayed
  - Optional API tokens (SHA-256 hashed) and source-IP ACL for feeds
  - Write API: add/remove bans over HTTP with a token (off by default,
    double-gated: global setting + per-token write flag)
  - Paginated ban and audit views (100/page, JS-free prev/next links)
  - Argon2id passwords, CSRF tokens, session pinning, brute-force
    lockout, strict CSP, HSTS
  - Optional "remember me" persistent login (off by default; rotating
    selector/validator tokens, config-gated), with per-device
    self-service revocation on the profile page
  - UI-tunable idle session timeout (separate from the absolute TTL)
  - Audit log of all admin actions
  - Migration system: install.php applies sql/migrations/*.sql and
    auto-locks once done


LAYOUT
------

  php-banlist/
    .htaccess               rewrites + file denies (Apache)
    nginx.conf.example      the same protections for Nginx installs
    config.example.php      copy to config.php
    index.php               dashboard
    login.php / logout.php
    ip-bans.php             manage IPs / CIDRs
    fqdn-bans.php           manage FQDNs
    users.php               superadmin: user CRUD
    settings.php            superadmin: timeouts, tokens, TZ default
    tokens.php              superadmin: issue/revoke API tokens
    profile.php             self-service TZ, password, remembered devices
    audit.php               audit log viewer
    list.php                public feed emitter
    api.php                 write API (token-authenticated add/remove)
    install.php             apply migrations + create first admin
    private/                server-side includes (Require all denied)
    assets/                 css (deny PHP execution)
    cron/                   CLI only (Require all denied)
      expire.php            hard-delete expired bans, prune logs
    sql/migrations/         numbered .sql; install.php applies in order
    INSTALL.txt
    CHANGELOG.txt
    LICENSE


WRITE API
---------

Disabled by default. To use it: enable "write API" on the settings
page, then issue (or re-issue) a token with the "allow write" flag on
the tokens page. Tokens issued before either flag is set stay
read-only. POST only; token in the X-API-Token header (preferred) or a
token= field. Form-encoded or JSON bodies.

  Fields:
    action    add | remove
    type      ip | fqdn        (token scope must cover it)
    value     one entry, or several separated by newlines/commas
    reason    optional, add only (<=255 chars)
    duration  optional, add only: 30s 30m 2h 7d 2w 1mo 1y p
              (blank = system default from settings)

  Examples:
    curl -X POST -H 'X-API-Token: TOKEN' \
         -d 'action=add&type=ip&value=203.0.113.5&reason=ssh scans&duration=7d' \
         https://host/php-banlist/api.php
      -> {"ok":true,"added":1,"invalid":[]}

    curl -X POST -H 'X-API-Token: TOKEN' \
         -d 'action=remove&type=fqdn&value=bad.example.com' \
         https://host/php-banlist/api.php
      -> {"ok":true,"removed":1,"not_found":[],"invalid":[]}

Optionally restrict callers by source IP with the api_acl block in
config.php (separate from the feed list_acl). All API writes appear in
the audit log as api_*_ban_* under "token:<label>".


See INSTALL.txt for setup, CHANGELOG.txt for release notes.
MIT licensed.
