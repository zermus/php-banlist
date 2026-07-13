<?php
/**
 * Auth: session bootstrap, login, logout, role checks, brute-force protection.
 */
declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/functions.php';

/**
 * Cookie path shared by the session and remember-me cookies. Scopes the
 * cookies to the app's mount point so a multi-app host stays tidy.
 */
function session_cookie_path(): string {
    $bp = base_path();
    return $bp === '' ? '/' : $bp . '/';
}

/**
 * Drop authenticated session state but keep the session container alive, so a
 * valid remember-me cookie can repopulate it in the same request. Used for
 * expected expiries (absolute TTL / idle timeout), not for hijack suspicion.
 */
function session_reset_auth(): void {
    $_SESSION = [];
    session_regenerate_id(true);
}

function session_boot(): void {
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    $cfg    = load_config();
    $s      = $cfg['session'];
    $secure = secure_cookies();

    // Session storage tuned for security
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.cookie_secure', $secure ? '1' : '0');
    ini_set('session.gc_maxlifetime', (string)$s['absolute_ttl']);

    session_name($s['name']);
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => session_cookie_path(),
        'domain'   => '',
        'secure'   => $secure,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();

    $now = time();

    if (!empty($_SESSION['uid'])) {
        // Idle (inactivity) timeout is UI-tunable via the settings table.
        // 0 disables it. Only read it for an established session.
        $idle_max = max(0, (int)setting('session_timeout_minutes', '30')) * 60;

        $expired = false;
        // Hard absolute lifetime, regardless of activity
        if (empty($_SESSION['started']) || ($now - (int)$_SESSION['started']) > (int)$s['absolute_ttl']) {
            $expired = true;
        }
        // Inactivity timeout
        if (!$expired && $idle_max > 0
            && !empty($_SESSION['last_activity'])
            && ($now - (int)$_SESSION['last_activity']) > $idle_max) {
            $expired = true;
        }

        if ($expired) {
            // Expected logout: clear auth, but a remember-me cookie may
            // transparently log the user back in below.
            session_reset_auth();
        } else {
            // Pin session to user agent to mitigate hijack. A mismatch is
            // treated as hostile: hard-destroy and burn the persistent token.
            $ua_hash = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
            if (($_SESSION['ua_hash'] ?? '') !== $ua_hash) {
                remember_clear();
                session_destroy_full();
                return;
            }
        }
    }

    // Fresh visit, or a session that just expired: try the remember-me cookie.
    if (empty($_SESSION['uid'])) {
        remember_login_from_cookie();
    }

    // Maintain an active session: periodic ID rotation + activity stamp.
    if (!empty($_SESSION['uid'])) {
        if (empty($_SESSION['last_regen']) || ($now - (int)$_SESSION['last_regen']) > (int)$s['regen_every']) {
            session_regenerate_id(true);
            $_SESSION['last_regen'] = $now;
        }
        $_SESSION['last_activity'] = $now;
    }
}

function session_destroy_full(): void {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(), '', time() - 42000,
            $params['path'], $params['domain'],
            $params['secure'], $params['httponly']
        );
    }
    session_destroy();
}

function current_user(): ?array {
    if (empty($_SESSION['uid'])) {
        return null;
    }
    static $cached = null;
    if ($cached !== null) {
        return $cached;
    }
    $stmt = db()->prepare('SELECT id, username, role, timezone FROM users WHERE id = ?');
    $stmt->execute([(int)$_SESSION['uid']]);
    $cached = $stmt->fetch() ?: null;
    return $cached;
}

function require_login(): array {
    session_boot();
    $u = current_user();
    if (!$u) {
        header('Location: ' . base_path() . '/login.php');
        exit;
    }
    return $u;
}

function require_role(string ...$roles): array {
    $u = require_login();
    if (!in_array($u['role'], $roles, true)) {
        http_response_code(403);
        echo '<!doctype html><meta charset=utf-8><title>403</title>';
        echo '<pre>403 Forbidden. Role required: ' . htmlspecialchars(implode(', ', $roles)) . '</pre>';
        exit;
    }
    return $u;
}

function role_can_write(array $u): bool {
    return in_array($u['role'], ['admin','superadmin'], true);
}

function role_can_admin_users(array $u): bool {
    return $u['role'] === 'superadmin';
}

/**
 * Attempt login. Returns true on success.
 * Rate-limited per IP and per account via the consolidated login_policy().
 * When $remember is true and remember-me is enabled in config, a persistent
 * login cookie is issued on success.
 */
function attempt_login(string $username, string $password, bool $remember = false): bool {
    $ip  = client_ip();
    $pol = login_policy();

    // Per-IP global throttle (operator hard floor)
    $stmt = db()->prepare(
        "SELECT COUNT(*) AS c FROM login_attempts
         WHERE ip_address = ? AND success = 0
           AND attempted_at > (NOW() - INTERVAL ? MINUTE)"
    );
    $stmt->execute([$ip, $pol['per_ip_window_min']]);
    $ip_fails = (int)($stmt->fetch()['c'] ?? 0);
    if ($ip_fails >= $pol['per_ip_max_attempts']) {
        record_attempt($ip, $username, false);
        return false;
    }

    // Lookup user (constant-time-ish: always verify a hash to mask timing)
    $stmt = db()->prepare('SELECT id, username, password_hash, role, failed_attempts, locked_until FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    $max_fail = $pol['max_failed_logins'];
    $lock_min = $pol['lockout_minutes'];

    if (!$user) {
        // Dummy verify to even out timing
        password_verify($password, '$2y$12$abcdefghijklmnopqrstuuQ8WXTjqVuYkVZl0gw6OUOnE6c4yJh2.G');
        record_attempt($ip, $username, false);
        return false;
    }

    // Account lockout window
    if ($user['locked_until'] && strtotime($user['locked_until']) > time()) {
        record_attempt($ip, $username, false);
        return false;
    }

    if (!password_verify($password, $user['password_hash'])) {
        $fails = (int)$user['failed_attempts'] + 1;
        $lock  = null;
        if ($fails >= $max_fail) {
            $lock = gmdate('Y-m-d H:i:s', time() + $lock_min * 60);
            $fails = 0;
        }
        $upd = db()->prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?');
        $upd->execute([$fails, $lock, $user['id']]);
        record_attempt($ip, $username, false);
        return false;
    }

    // Rehash if cost factors have moved
    if (password_needs_rehash($user['password_hash'], password_algo_default())) {
        $new_hash = password_hash($password, password_algo_default());
        db()->prepare('UPDATE users SET password_hash = ? WHERE id = ?')
            ->execute([$new_hash, $user['id']]);
    }

    // Reset counters, stamp login
    db()->prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = UTC_TIMESTAMP(), last_login_ip = ? WHERE id = ?')
        ->execute([$ip, $user['id']]);

    // Establish session
    session_regenerate_id(true);
    $_SESSION['uid']           = (int)$user['id'];
    $_SESSION['started']       = time();
    $_SESSION['last_regen']    = time();
    $_SESSION['last_activity'] = time();
    $_SESSION['ua_hash']       = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');

    if ($remember) {
        remember_issue((int)$user['id']);
    }

    record_attempt($ip, $username, true);
    audit_log_write($user['id'], $user['username'], 'login', $username, null);
    return true;
}

function record_attempt(string $ip, string $username, bool $success): void {
    $stmt = db()->prepare(
        'INSERT INTO login_attempts (ip_address, username, success) VALUES (?, ?, ?)'
    );
    $stmt->execute([$ip, $username, $success ? 1 : 0]);
}

/* -------------------- Remember-me (persistent login) -------------------- */

/**
 * Normalized remember-me config from config.php. Disabled unless the operator
 * opts in. Duration is clamped to 1..90 days. Kept in config (not the
 * settings table) because it is consulted on the unauthenticated bootstrap
 * path, and because disabling persistent logins should be an operator
 * decision, not something a compromised UI session can toggle.
 */
function remember_cfg(): array {
    $cfg = load_config();
    $r   = $cfg['remember_me'] ?? [];
    return [
        'enabled' => !empty($r['enabled']),
        'days'    => max(1, min(90, (int)($r['days'] ?? 7))),
        'cookie'  => (string)($r['cookie'] ?? 'pbl_remember'),
    ];
}

/**
 * Set (or, with a past expiry, clear) the remember-me cookie using the same
 * hardening flags as the session cookie.
 */
function remember_set_cookie(string $value, int $expires): void {
    setcookie(remember_cfg()['cookie'], $value, [
        'expires'  => $expires,
        'path'     => session_cookie_path(),
        'domain'   => '',
        'secure'   => secure_cookies(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

/**
 * Issue a new remember-me token and set the cookie. Selector/validator split:
 * the selector is a public lookup handle; the validator is a secret compared
 * in constant time against its stored SHA-256. Only the hash is persisted, so
 * a database read alone never yields a usable cookie.
 */
function remember_issue(int $user_id): void {
    $rc = remember_cfg();
    if (!$rc['enabled']) return;

    $selector  = bin2hex(random_bytes(16)); // 32 hex chars
    $validator = bin2hex(random_bytes(32)); // 64 hex chars
    $expires   = gmdate('Y-m-d H:i:s', time() + $rc['days'] * 86400);
    $ua_hash   = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');

    db()->prepare(
        'INSERT INTO remember_tokens (user_id, selector, validator_hash, expires_at, user_agent_hash)
         VALUES (?, ?, ?, ?, ?)'
    )->execute([$user_id, $selector, hash('sha256', $validator), $expires, $ua_hash]);

    remember_set_cookie($selector . ':' . $validator, time() + $rc['days'] * 86400);
}

/**
 * Validate a remember-me cookie and, on success, establish a session and
 * rotate the token (new selector + validator, original fixed expiry).
 * A matched selector with a bad validator is treated as theft: every token
 * for that user is purged. Returns true if a session was established.
 */
function remember_login_from_cookie(): bool {
    $rc = remember_cfg();
    if (!$rc['enabled']) return false;

    $raw = (string)($_COOKIE[$rc['cookie']] ?? '');
    if ($raw === '' || strpos($raw, ':') === false) return false;

    [$selector, $validator] = explode(':', $raw, 2);
    if (strlen($selector) !== 32 || strlen($validator) !== 64
        || !ctype_xdigit($selector) || !ctype_xdigit($validator)) {
        remember_set_cookie('', time() - 42000);
        return false;
    }

    $stmt = db()->prepare(
        'SELECT id, user_id, validator_hash, expires_at, user_agent_hash
         FROM remember_tokens WHERE selector = ?'
    );
    $stmt->execute([$selector]);
    $row = $stmt->fetch();

    if (!$row) {
        remember_set_cookie('', time() - 42000);
        return false;
    }
    if (strtotime($row['expires_at'] . ' UTC') <= time()) {
        db()->prepare('DELETE FROM remember_tokens WHERE id = ?')->execute([(int)$row['id']]);
        remember_set_cookie('', time() - 42000);
        return false;
    }

    // Constant-time validator comparison
    if (!hash_equals((string)$row['validator_hash'], hash('sha256', $validator))) {
        // Selector hit but validator wrong: likely stolen/forged. Burn all
        // of this user's persistent tokens as a precaution.
        db()->prepare('DELETE FROM remember_tokens WHERE user_id = ?')->execute([(int)$row['user_id']]);
        remember_set_cookie('', time() - 42000);
        return false;
    }

    // Optional UA pin (defense in depth)
    if (!empty($row['user_agent_hash'])) {
        $ua_hash = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
        if (!hash_equals((string)$row['user_agent_hash'], $ua_hash)) {
            db()->prepare('DELETE FROM remember_tokens WHERE id = ?')->execute([(int)$row['id']]);
            remember_set_cookie('', time() - 42000);
            return false;
        }
    }

    // User must still exist
    $ustmt = db()->prepare('SELECT id, username FROM users WHERE id = ?');
    $ustmt->execute([(int)$row['user_id']]);
    $user = $ustmt->fetch();
    if (!$user) {
        db()->prepare('DELETE FROM remember_tokens WHERE id = ?')->execute([(int)$row['id']]);
        remember_set_cookie('', time() - 42000);
        return false;
    }

    // Rotate the token: new selector + validator, same expiry (fixed window).
    $new_selector  = bin2hex(random_bytes(16));
    $new_validator = bin2hex(random_bytes(32));
    db()->prepare(
        'UPDATE remember_tokens
         SET selector = ?, validator_hash = ?, last_used_at = UTC_TIMESTAMP()
         WHERE id = ?'
    )->execute([$new_selector, hash('sha256', $new_validator), (int)$row['id']]);

    $ttl_left = strtotime($row['expires_at'] . ' UTC') - time();
    remember_set_cookie($new_selector . ':' . $new_validator, time() + max(60, $ttl_left));

    // Establish the session
    session_regenerate_id(true);
    $_SESSION['uid']           = (int)$user['id'];
    $_SESSION['started']       = time();
    $_SESSION['last_regen']    = time();
    $_SESSION['last_activity'] = time();
    $_SESSION['ua_hash']       = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');

    audit_log_write((int)$user['id'], $user['username'], 'login_remember', $user['username'], null);
    return true;
}

/**
 * Selector half of the remember-me cookie presented by THIS browser, or null
 * if absent/malformed. Used by the profile page to badge "this device" and
 * to decide which token to spare when burning the rest.
 */
function remember_current_selector(): ?string {
    $raw = (string)($_COOKIE[remember_cfg()['cookie']] ?? '');
    if ($raw === '' || strpos($raw, ':') === false) return null;
    [$selector] = explode(':', $raw, 2);
    return (strlen($selector) === 32 && ctype_xdigit($selector)) ? $selector : null;
}

/**
 * Revoke every remember-me token for a user EXCEPT the one belonging to the
 * current browser (if any). Returns the number revoked. Used on password
 * change and by the profile "sign out other devices" action.
 */
function remember_revoke_others(int $user_id): int {
    $keep = remember_current_selector();
    if ($keep !== null) {
        $stmt = db()->prepare('DELETE FROM remember_tokens WHERE user_id = ? AND selector <> ?');
        $stmt->execute([$user_id, $keep]);
    } else {
        $stmt = db()->prepare('DELETE FROM remember_tokens WHERE user_id = ?');
        $stmt->execute([$user_id]);
    }
    return $stmt->rowCount();
}

/**
 * Revoke the current remember-me token server-side and expire the cookie.
 * Called on logout and on suspected session hijack.
 */
function remember_clear(): void {
    $rc  = remember_cfg();
    $raw = (string)($_COOKIE[$rc['cookie']] ?? '');
    if ($raw !== '' && strpos($raw, ':') !== false) {
        [$selector] = explode(':', $raw, 2);
        if (strlen($selector) === 32 && ctype_xdigit($selector)) {
            try {
                db()->prepare('DELETE FROM remember_tokens WHERE selector = ?')->execute([$selector]);
            } catch (Throwable $e) {
                // Best effort; the cookie is expired below regardless.
            }
        }
    }
    remember_set_cookie('', time() - 42000);
}

function password_algo_default(): string {
    return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
}

function validate_password_policy(string $pw): ?string {
    $cfg = load_config();
    $p = $cfg['passwords'];
    if (strlen($pw) < (int)$p['min_length']) {
        return 'Password must be at least ' . (int)$p['min_length'] . ' characters.';
    }
    if (!empty($p['require_mixed'])) {
        if (!preg_match('/[a-z]/', $pw) || !preg_match('/[A-Z]/', $pw)
            || !preg_match('/\d/', $pw) || !preg_match('/[^A-Za-z0-9]/', $pw)) {
            return 'Password must contain upper, lower, digit, and symbol.';
        }
    }
    return null;
}
