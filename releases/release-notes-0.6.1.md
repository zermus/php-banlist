# php-banlist 0.6.1

Ban-scope guardrail correction. **No schema changes** — upgrading from 0.6 is a file swap; re-running `install.php` is not required.

## Highlights

- **Safe whole-family targets.** IPv4/IPv6 `/0` and unspecified targets (`0.0.0.0`, `0.0.0.0/32`, `::`, and `::/128`) are rejected and suppressed from feeds by default. A separate audited superadmin switch can enable them, but they remain confirmation-required.
- **Policy-bound web confirmation.** Warning-level and enabled dangerous web additions stop at a server-rendered, CSRF-protected confirmation bound to the exact request and current policy. Its random token expires after ten minutes and is consumed on the first attempt, preventing replay or hidden-field bypass. Confirmed additions are audited.
- **Exact API override.** API IP additions preflight every entry before writing. Warning-level and enabled dangerous requests require the exact `confirm_broad_subnets=yes` field; that override never permits entries disabled by policy. Successful bulk additions and their audit rows share one transaction.
- **Safe feed and setting behavior.** Only the exact stored value `1` enables whole-family targets. Missing or malformed settings fall back safely, and feeds apply the current policy to legacy rows.
- **Focused regression coverage.** Dependency-free checks cover IPv4/IPv6 unspecified and `/0` targets, confirmation policy changes, API override exactness, and feed suppression.

## Install

Fresh install: extract `php-banlist-0.6.1.tar.gz` or `.zip`, create the database, copy `config.example.php` to `config.php`, and open `install.php`. Full walkthrough in `INSTALL.txt` (Apache: section 4; Nginx: section 4b).

## Upgrade from 0.6

Extract 0.6.1 alongside 0.6, copy the existing `config.php` into `php-banlist-0.6.1/`, and point the stable `php-banlist` symlink at the new directory. No database migration is needed. To roll back, point the symlink back to `php-banlist-0.6`.

## Requirements

Apache 2.4 + mod_rewrite or Nginx + php-fpm, PHP 8.0+, MariaDB 10.6+ / MySQL 8.0+.

MIT licensed.
