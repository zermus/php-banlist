<?php
/**
 * php-banlist configuration
 * Copy to config.php and edit for your environment.
 * NEVER commit config.php to source control.
 */

return [
    // Database (use a dedicated MySQL user with only the privileges this app needs)
    'db' => [
        'host'    => '127.0.0.1',
        'port'    => 3306,
        'name'    => 'banlist',
        'user'    => 'banlist',
        'pass'    => 'CHANGE_ME',
        'charset' => 'utf8mb4',
        // Optional: if set, TCP host/port are ignored and the Unix socket is used.
        // Recommended for local LAMP installs (faster, no TCP overhead).
        // 'socket' => '/var/run/mysqld/mysqld.sock',
    ],

    // Site
    'site' => [
        // base_path is auto-detected from $_SERVER['SCRIPT_NAME'] by default.
        // Override only if rewrites or symlinks confuse the detection.
        // 'base_path' => '/php-banlist',

        // Application name shown in the UI
        'name' => 'php-banlist',

        // 'auto' (default), true, or false.
        // 'auto' uses HTTPS only when the request itself is HTTPS, which is
        // correct for any sane deployment including ones behind a proxy that
        // sets X-Forwarded-Proto (see 'trusted_proxies' below).
        'secure_cookies' => 'auto',
    ],

    // Session
    'session' => [
        'name'         => 'pbl_sid',
        // Hard absolute lifetime in seconds, regardless of activity
        'absolute_ttl' => 28800, // 8 hours
        // Regenerate session ID every N seconds to limit fixation window
        'regen_every'  => 900,   // 15 minutes
        // Note: the idle (inactivity) timeout is UI-tunable on the settings
        // page (session_timeout_minutes; 0 disables it). It is separate from
        // absolute_ttl above, which is the operator-set hard ceiling.
    ],

    // Remember-me (persistent login) cookie.
    // When enabled, the login page offers a "stay signed in" checkbox that
    // issues a rotating selector/validator token, letting a session survive
    // browser restarts and idle/absolute expiry for up to 'days'. Disabled by
    // default. Kept here (not in the settings table) because it is consulted
    // on the unauthenticated bootstrap path and disabling it should require
    // config access, not just a UI session.
    'remember_me' => [
        'enabled' => false,
        'days'    => 7,            // clamped to 1..90
        'cookie'  => 'pbl_remember',
    ],

    // Brute-force protection (DB-level).
    // The effective policy is read through a single accessor, login_policy(),
    // which merges these operator-set per-IP limits with the UI-tunable
    // per-account thresholds from the settings table (max_failed_logins,
    // lockout_minutes). Per-IP stays here as a hard floor on purpose: a
    // compromised UI session must not be able to loosen it.
    'login_protection' => [
        'per_ip_max_attempts' => 20,   // failed attempts from one IP
        'per_ip_window_min'   => 15,   // sliding window in minutes
    ],

    // Password policy (Argon2id when available, BCRYPT fallback)
    'passwords' => [
        'min_length'    => 14,
        'require_mixed' => true,  // upper, lower, digit, symbol
    ],

    // Optional: restrict who can fetch the .txt lists.
    // Leave empty array to allow any source.
    // Use CIDR notation. Both v4 and v6 supported.
    'list_acl' => [
        // '10.5.5.0/24',
        // '10.3.3.0/24',
        // '203.0.113.10/32',
    ],

    // Optional: restrict which source IPs may call the write API (api.php).
    // Separate from list_acl above. Leave empty to allow any source; the API
    // is still gated by the enable_write_api setting and per-token write
    // flags either way. Use CIDR notation. Both v4 and v6 supported.
    'api_acl' => [
        // '10.5.5.0/24',
    ],

    // Data retention for the nightly cron (cron/expire.php). Expired bans are
    // always removed; these control how long the rolling logs are kept.
    // Minimum 1 day each. Remember-me tokens are pruned at their own expiry.
    'retention' => [
        'login_attempts_days' => 30,
        'audit_log_days'      => 365,
    ],

    // Trust X-Forwarded-For and X-Forwarded-Proto from these proxies (CIDR).
    // Empty = ignore both headers.
    'trusted_proxies' => [
        // '127.0.0.1/32',
    ],
];
