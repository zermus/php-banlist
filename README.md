# php-banlist

**Version 0.1** &middot; [CHANGELOG](CHANGELOG.txt) &middot; Apache 2.0 licensed

Self-hosted manager for dynamic firewall banlists. Web UI for managing IPs/CIDRs and FQDNs, two feed URLs that any URL-driven firewall can consume:

```
<base>/IP-list.txt    one IPv4/IPv6 or CIDR per line
<base>/FQDN-list.txt  one hostname per line
```

> Both URLs are rewritten to `list.php` and generated on every request from the database. No static file on disk; you won't see them in `ls`. Add or remove a ban and the next fetch reflects it immediately.

Plain text, one entry per line, `#` comment header, UTF-8 - the universal format any URL-driven firewall accepts.

## Requirements

- Apache 2.4 with `mod_rewrite` (`mod_headers`, `mod_expires` recommended)
- PHP 8.0+ (tested on 8.3)
- MariaDB 10.6+ or MySQL 8.0+
- PHP extensions: `pdo`, `pdo_mysql`, `session`, `mbstring`, `openssl`, `filter`, `hash`

## Features

- Three roles: readonly, admin, superadmin
- Per-entry expiry with calendar-accurate durations: `s`/`m`/`h`/`d`/`w`/`mo`/`y`/`p`
- Per-user timezone (US, Europe, Russia, Japan, India, Australia presets); UTC stored, local-time displayed
- Optional API tokens (SHA-256 hashed) and source-IP ACL for the feeds
- Argon2id passwords, CSRF tokens, session pinning, brute-force lockout, strict CSP, HSTS
- Audit log of all admin actions
- Migration system: `install.php` applies `sql/migrations/*.sql` and auto-locks once done

## Install

```sh
# 1. files. Extract under your document root (or wherever you want
#    the app served). A symlink `php-banlist` points at the active
#    release - re-point it to roll back or upgrade.
cd /path/to/document-root
tar xzf php-banlist-0.1.tar.gz
sudo ln -s php-banlist-0.1 php-banlist
cd php-banlist
sudo chown -R apache:apache .
sudo find . -type d -exec chmod 750 {} \;
sudo find . -type f -exec chmod 640 {} \;

# 2. database (DDL grants needed at install time; revoke after if you want)
sudo mysql <<'SQL'
CREATE DATABASE banlist CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'banlist'@'localhost' IDENTIFIED BY 'CHANGE_ME';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES
    ON banlist.* TO 'banlist'@'localhost';
FLUSH PRIVILEGES;
SQL

# 3. config
sudo cp config.example.php config.php
sudo $EDITOR config.php           # set db.pass
sudo chown root:apache config.php
sudo chmod 640 config.php

# 4. apache: most LAMP installs need nothing; see INSTALL.txt §4 if
#    AllowOverride is locked down on your DocumentRoot

# 5. install: open https://your-server/php-banlist/install.php,
#    create the first superadmin, delete install.php after
sudo rm install.php

# 6. cron (nightly expiry + log pruning, as apache user)
echo "3 4 * * * /usr/bin/php /path/to/php-banlist/cron/expire.php" \
    | sudo -u apache crontab -
```

## Upgrade

Extract the new version next to the old, carry the config forward, re-point the symlink, then run `install.php` in a browser to apply new migrations.

```sh
cd /path/to/document-root
tar xzf php-banlist-0.2.tar.gz
sudo cp php-banlist/config.php php-banlist-0.2/
sudo chown -R apache:apache php-banlist-0.2
sudo find php-banlist-0.2 -type d -exec chmod 750 {} \;
sudo find php-banlist-0.2 -type f -exec chmod 640 {} \;
sudo ln -sfn php-banlist-0.2 php-banlist        # atomic swap
```

To roll back: `sudo ln -sfn php-banlist-0.1 php-banlist`.

Full setup notes in [INSTALL.txt](INSTALL.txt).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
