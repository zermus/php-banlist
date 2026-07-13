# php-banlist 0.5

Nginx support + security hardening. **No schema changes** — upgrading from 0.4 is just the file swap (INSTALL.txt section 9); re-running install.php is not required.

## Highlights

- **Nginx support.** Nginx is now a supported web server alongside Apache. The new `nginx.conf.example` translates every shipped `.htaccess` protection one-for-one — the `private/`, `cron/`, `sql/`, `config.php`, dotfile, and source-extension denies; the `IP-list.txt` / `FQDN-list.txt` feed rewrites (query strings pass through, so `?token=` keeps working); and the no-PHP-execution rule under `assets/`. Each block is commented with the Apache rule it mirrors, and INSTALL.txt section 4b walks through setup with curl sanity checks that the deny rules actually took.
- **Logout is now POST + CSRF.** Previously any cross-site GET (an `<img>` tag, a forced navigation) could end your session and burn your remember-me token. The nav logout link is now a styled POST form; a bare GET of `logout.php` harmlessly redirects to the dashboard.
- **Open-redirect fix in login `?next=`.** The same-app path check allowed a backslash as the first path character, and browsers normalize `Location: /\evil.com` to the protocol-relative `//evil.com`. Backslashes in redirect targets are now rejected.

## Install

Fresh install: extract, create the database, copy `config.example.php` to `config.php`, open `install.php`. Full walkthrough in INSTALL.txt (Apache: section 4; Nginx: section 4b).

## Requirements

Apache 2.4 + mod_rewrite or Nginx + php-fpm, PHP 8.0+, MariaDB 10.6+ / MySQL 8.0+.

MIT licensed.
