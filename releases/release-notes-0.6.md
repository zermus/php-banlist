# php-banlist 0.6

Ban-scope safety release. **No schema changes** — upgrading from 0.5 is a file swap; re-running `install.php` is not required.

## Highlights

- **Dangerous whole-family bans are rejected.** The shared IP/CIDR validator now rejects IPv4 and IPv6 `/0` entries, including non-canonical forms such as `203.0.113.7/0` and `2001:db8::1/0`. This policy applies to web UI and write API additions, while feed validation suppresses unsafe legacy `/0` rows already stored.
- **CIDR ACL validation is stricter.** Malformed and out-of-range prefix lengths are rejected instead of being coerced or reaching invalid packed-address offsets.
- **Regression checks.** A small dependency-free test script covers accepted ban targets, rejected `/0` targets, and source-IP ACL prefix bounds.

## Install

Fresh install: extract, create the database, copy `config.example.php` to `config.php`, open `install.php`. Full walkthrough in `INSTALL.txt` (Apache: section 4; Nginx: section 4b).

## Requirements

Apache 2.4 + mod_rewrite or Nginx + php-fpm, PHP 8.0+, MariaDB 10.6+ / MySQL 8.0+.

MIT licensed.
