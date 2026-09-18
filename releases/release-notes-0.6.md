# php-banlist 0.6

Ban-scope safety release. **No schema changes** — upgrading from 0.5 is a file swap; re-running `install.php` is not required.

## Highlights

- **Configurable subnet guard rails.** Superadmins can set separate IPv4 and IPv6 warning and hard-rejection CIDR prefix lengths. Defaults warn at IPv4 `/24`-or-broader and IPv6 `/64`-or-broader. IPv4 and IPv6 `/0` remain unconditionally rejected.
- **Deliberate broad-add confirmation.** Warning-level web additions stop at a server-rendered, CSRF-protected confirmation bound to the exact request. Its random token expires after ten minutes and is consumed on the first attempt, preventing replay or hidden-field bypass. Confirmed broad adds are audited.
- **Atomic API policy.** API IP additions preflight every entry before writing. Invalid or hard-rejected mixed requests write nothing. Warning-level requests require the exact `confirm_broad_subnets=yes` field; that override never permits hard-rejected entries. Successful bulk additions and their audit rows share one transaction.
- **Safe malformed-setting behavior.** Missing or malformed settings fall back to safe defaults, out-of-range prefixes are clamped, conflicting warning cutoffs are raised to the hard cutoff, and `/0` cannot be weakened. Setting changes are audited.
- **Legacy cleanup remains possible.** Removals still normalize legacy `/0` rows, while feeds suppress entries at or broader than the active hard cutoff.
- **CIDR ACL validation is stricter.** Malformed and out-of-range prefix lengths are rejected instead of being coerced or reaching invalid packed-address offsets.
- **Focused regression checks.** Dependency-free checks cover IPv4/IPv6 boundaries, malformed settings, mixed bulk preflight, API override exactness, confirmation replay/bypass, `/0` safety, and ACL prefix bounds.

## Install

Fresh install: extract, create the database, copy `config.example.php` to `config.php`, open `install.php`. Full walkthrough in `INSTALL.txt` (Apache: section 4; Nginx: section 4b).

## Requirements

Apache 2.4 + mod_rewrite or Nginx + php-fpm, PHP 8.0+, MariaDB 10.6+ / MySQL 8.0+.

MIT licensed.
