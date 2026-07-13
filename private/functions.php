<?php
/**
 * Shared helpers used across pages.
 */
declare(strict_types=1);

require_once __DIR__ . '/db.php';

/* -------------------- Output escaping -------------------- */

function e(?string $s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/* -------------------- Base path / HTTPS auto-detection -------------------- */

/**
 * Resolve the URL path prefix the app is mounted under.
 * Returns "" when at docroot, otherwise "/sub/path" (no trailing slash).
 * Config value 'site.base_path' overrides auto-detection.
 */
function base_path(): string {
    static $cached = null;
    if ($cached !== null) {
        return $cached;
    }
    $cfg = load_config();
    if (!empty($cfg['site']['base_path'])) {
        return $cached = rtrim($cfg['site']['base_path'], '/');
    }
    $script = $_SERVER['SCRIPT_NAME'] ?? '';
    $dir    = str_replace('\\', '/', dirname($script));
    $dir    = rtrim($dir, '/');
    return $cached = ($dir === '.' || $dir === '/') ? '' : $dir;
}

/**
 * Is the current request HTTPS? Honors trusted_proxies for X-Forwarded-Proto.
 */
function is_https(): bool {
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') {
        return true;
    }
    if (($_SERVER['SERVER_PORT'] ?? null) == 443) {
        return true;
    }
    // Respect XFP only when the immediate peer is a trusted proxy.
    $cfg     = load_config();
    $trusted = $cfg['trusted_proxies'] ?? [];
    if ($trusted) {
        $remote = $_SERVER['REMOTE_ADDR'] ?? '';
        foreach ($trusted as $cidr) {
            if (ip_in_cidr($remote, $cidr)) {
                $xfp = strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''));
                if ($xfp === 'https') {
                    return true;
                }
                break;
            }
        }
    }
    return false;
}

/**
 * Resolve the 'secure_cookies' config to a real boolean.
 * 'auto' or missing -> follow is_https().
 */
function secure_cookies(): bool {
    $cfg = load_config();
    $v   = $cfg['site']['secure_cookies'] ?? 'auto';
    if ($v === 'auto') {
        return is_https();
    }
    return (bool)$v;
}

/* -------------------- CSRF -------------------- */

function csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_field(): string {
    return '<input type="hidden" name="csrf" value="' . e(csrf_token()) . '">';
}

function csrf_check(): void {
    $supplied = (string)($_POST['csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    if (!hash_equals($_SESSION['csrf'] ?? '', $supplied)) {
        http_response_code(400);
        exit('CSRF token mismatch.');
    }
}

/* -------------------- HTTP method guards -------------------- */

function require_post(): void {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        http_response_code(405);
        header('Allow: POST');
        exit('Method Not Allowed');
    }
}

/* -------------------- Client IP -------------------- */

function client_ip(): string {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $cfg    = load_config();
    $trusted = $cfg['trusted_proxies'] ?? [];
    if (!$trusted) {
        return $remote;
    }
    foreach ($trusted as $cidr) {
        if (ip_in_cidr($remote, $cidr)) {
            $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
            if ($xff) {
                $first = trim(explode(',', $xff)[0]);
                if (filter_var($first, FILTER_VALIDATE_IP)) {
                    return $first;
                }
            }
            break;
        }
    }
    return $remote;
}

function ip_in_cidr(string $ip, string $cidr): bool {
    if (strpos($cidr, '/') === false) {
        $cidr .= filter_var($cidr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '/128' : '/32';
    }
    [$subnet, $mask] = explode('/', $cidr, 2);
    $mask = (int)$mask;

    $ip_bin     = @inet_pton($ip);
    $subnet_bin = @inet_pton($subnet);
    if ($ip_bin === false || $subnet_bin === false || strlen($ip_bin) !== strlen($subnet_bin)) {
        return false;
    }
    $bytes = intdiv($mask, 8);
    $bits  = $mask % 8;
    if ($bytes > 0 && substr($ip_bin, 0, $bytes) !== substr($subnet_bin, 0, $bytes)) {
        return false;
    }
    if ($bits === 0) {
        return true;
    }
    $mask_byte = chr((0xFF << (8 - $bits)) & 0xFF);
    return (ord($ip_bin[$bytes]) & ord($mask_byte)) === (ord($subnet_bin[$bytes]) & ord($mask_byte));
}

/* -------------------- IP / CIDR / URL validation -------------------- */

/**
 * Validates a single IP or CIDR (v4 or v6). Returns normalized string or null.
 */
function normalize_ip_or_cidr(string $input): ?string {
    $input = trim($input);
    if ($input === '') return null;

    if (strpos($input, '/') !== false) {
        [$addr, $mask] = explode('/', $input, 2);
        $addr = trim($addr);
        $mask = trim($mask);
        if (!ctype_digit($mask)) return null;
        $mask = (int)$mask;
        $bin = @inet_pton($addr);
        if ($bin === false) return null;
        $is_v6 = strlen($bin) === 16;
        if ($is_v6 && ($mask < 0 || $mask > 128)) return null;
        if (!$is_v6 && ($mask < 0 || $mask > 32))  return null;
        return inet_ntop($bin) . '/' . $mask;
    }

    $bin = @inet_pton($input);
    if ($bin === false) return null;
    return inet_ntop($bin);
}

/**
 * Validates a hostname (DNS name) or full URL. Returns normalized lowercase string or null.
 * pfBlockerNG / DNSBL style: hostnames only. We strip scheme/path if a URL was pasted.
 */
function normalize_hostname(string $input): ?string {
    $input = trim($input);
    if ($input === '') return null;

    // If they pasted a URL, extract host
    if (preg_match('~^[a-z][a-z0-9+\-.]*://~i', $input)) {
        $parts = parse_url($input);
        if (empty($parts['host'])) return null;
        $input = $parts['host'];
    }

    $input = strtolower($input);
    // Strip trailing dot
    $input = rtrim($input, '.');

    // Length check
    if (strlen($input) < 1 || strlen($input) > 253) return null;

    // RFC 1123 hostname check (allows IDN punycode 'xn--' labels)
    if (!preg_match('/^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/', $input)
        && !preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $input)) {
        return null;
    }
    return $input;
}

/* -------------------- Duration parsing -------------------- */

/**
 * Curated list of duration shortcuts shown in the UI:
 *   s  = seconds        m = minutes        h = hours
 *   d  = days           w = weeks
 *   mo = months (calendar-accurate)        y = years (calendar-accurate)
 *   p  / permanent / forever / 0 / "" = permanent ban
 *
 * Returns ['seconds' => int|null, 'expires_at' => 'Y-m-d H:i:s' UTC|null,
 *          'permanent' => bool] or null on parse error.
 *
 * 'seconds' is provided for compatibility (e.g. storing the default timeout
 * in the settings table). For absolute-time math, prefer 'expires_at' which
 * is calendar-accurate for months and years.
 */
function parse_duration(string $s): ?array {
    $s = trim(strtolower($s));
    if ($s === '' || $s === 'permanent' || $s === 'forever' || $s === '0' || $s === 'p') {
        return ['seconds' => null, 'expires_at' => null, 'permanent' => true];
    }
    // 'mo' must come before 'm' in the alternation so it wins on greedy match.
    if (!preg_match('/^(\d+)\s*(mo|s|m|h|d|w|y)?$/', $s, $matches)) {
        return null;
    }
    $n = (int)$matches[1];
    $u = $matches[2] ?? 's';

    // Calendar-accurate expiry via DateInterval
    $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    $spec_map = [
        's'  => "PT{$n}S",
        'm'  => "PT{$n}M",
        'h'  => "PT{$n}H",
        'd'  => "P{$n}D",
        'w'  => "P{$n}W",
        'mo' => "P{$n}M",
        'y'  => "P{$n}Y",
    ];
    try {
        $expiry = $now->add(new DateInterval($spec_map[$u]));
    } catch (Exception $e) {
        return null;
    }

    // Fixed-seconds approximation for callers that store a duration (e.g. the
    // settings table). For mo/y we use the average so the default-timeout
    // setting can round-trip predictably.
    $sec_map = [
        's' => 1, 'm' => 60, 'h' => 3600,
        'd' => 86400, 'w' => 604800,
        'mo' => 2629800,   // ~30.44 days
        'y'  => 31557600,  // 365.25 days
    ];

    return [
        'seconds'    => $n * $sec_map[$u],
        'expires_at' => $expiry->format('Y-m-d H:i:s'),
        'permanent'  => false,
    ];
}

/**
 * Sanitize a duration shortcut arriving via ?dur= for safe reflection into
 * the add form's duration field. Returns the original token only if it is a
 * valid duration; otherwise ''. Output must still be escaped via e().
 */
function dur_prefill(): string {
    $d = (string)($_GET['dur'] ?? '');
    if ($d === '' || strlen($d) > 20) return '';
    return parse_duration($d) !== null ? $d : '';
}

/**
 * Preserve the current list view's filter state (q / expired) as a query
 * string, optionally merging in extra params. Returns '' when there is
 * nothing to carry, otherwise '?key=val&...'. Used to keep the user on the
 * same filtered view across duration picks and confirmation round-trips.
 */
function list_state_qs(array $extra = []): string {
    $params = [];
    $q = trim((string)($_GET['q'] ?? ''));
    if ($q !== '')                $params['q'] = $q;
    if (!empty($_GET['expired'])) $params['expired'] = '1';
    $p = pager_page();
    if ($p > 1)                   $params['page'] = $p;
    foreach ($extra as $k => $v) {
        $params[$k] = $v;
    }
    return $params ? ('?' . http_build_query($params)) : '';
}

/* -------------------- Pagination (JS-free) -------------------- */

/** Rows per page on the paginated list views. */
const PBL_PER_PAGE = 100;

/** Current 1-based page number from ?page=, clamped to >= 1. */
function pager_page(): int {
    $p = (int)($_GET['page'] ?? 1);
    return $p >= 1 ? $p : 1;
}

/**
 * Compute pagination window for a query. Clamps the requested page into
 * range so a stale link (e.g. after deletions shrank the set) lands on the
 * last real page instead of an empty one.
 * Returns ['page','pages','total','limit','offset'].
 */
function pager_window(int $total, int $per_page = PBL_PER_PAGE): array {
    $pages = max(1, (int)ceil($total / $per_page));
    $page  = min(pager_page(), $pages);
    return [
        'page'   => $page,
        'pages'  => $pages,
        'total'  => $total,
        'limit'  => $per_page,
        'offset' => ($page - 1) * $per_page,
    ];
}

/**
 * Render prev/next pager links plus a count summary. Pure GET links that
 * preserve the current q / expired filter state, so it works under the
 * strict no-JS CSP. Emits nothing when everything fits on one page.
 */
function pager_render(array $w): string {
    if ($w['pages'] <= 1) {
        return $w['total'] > 0
            ? '<div class="pager"><span class="pager-info">' . (int)$w['total'] . ' entries</span></div>'
            : '';
    }
    $out = '<div class="pager">';
    if ($w['page'] > 1) {
        $out .= '<a class="pager-link" href="' . e(list_state_qs(['page' => $w['page'] - 1])) . '">&laquo; prev</a>';
    } else {
        $out .= '<span class="pager-link disabled">&laquo; prev</span>';
    }
    $out .= '<span class="pager-info">page ' . (int)$w['page'] . ' of ' . (int)$w['pages']
          . ' &middot; ' . (int)$w['total'] . ' entries</span>';
    if ($w['page'] < $w['pages']) {
        $out .= '<a class="pager-link" href="' . e(list_state_qs(['page' => $w['page'] + 1])) . '">next &raquo;</a>';
    } else {
        $out .= '<span class="pager-link disabled">next &raquo;</span>';
    }
    return $out . '</div>';
}

/**
 * Build a duration-shortcut picker link for the list-management pages. The
 * link preserves the current search/filter state (q / expired), sets ?dur,
 * and jumps to the add form (#add). JS-free by design: the target page
 * reflects ?dur into the duration field via dur_prefill(), so this works
 * under the strict default-src 'none' CSP with no script-src.
 */
function dur_pick_link(string $code): string {
    return list_state_qs(['dur' => $code]) . '#add';
}

/* -------------------- JS-free confirmation interstitial -------------------- */

/**
 * Build a link to the confirmation interstitial for a destructive action.
 * Lands on the same page with ?confirm=ACTION&id=ID, preserving the current
 * q / expired filter state so confirm/cancel return to the same view.
 */
function confirm_link(string $action, int $id): string {
    return list_state_qs(['confirm' => $action, 'id' => $id]);
}

/**
 * If the current GET request is a confirmation prompt (?confirm=ACTION&id=ID)
 * with ACTION in the page's whitelist and a positive id, return
 * ['action' => ACTION, 'id' => ID]; otherwise null.
 */
function confirm_request(array $allowed): ?array {
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') return null;
    $a = (string)($_GET['confirm'] ?? '');
    if ($a === '' || !in_array($a, $allowed, true)) return null;
    $id = (int)($_GET['id'] ?? 0);
    if ($id <= 0) return null;
    return ['action' => $a, 'id' => $id];
}

/**
 * Render a JS-free confirmation card. The confirm button POSTs the real
 * {action, id} with a CSRF token; cancel is a link back to the filtered
 * list. Works under the strict default-src 'none' CSP because it needs no
 * script: the dead inline confirm() handlers this replaces never fired.
 *
 * $prompt_html is treated as HTML; callers MUST escape interpolated values.
 */
function confirm_card(string $self_url, string $prompt_html, string $action, int $id, string $confirm_label = 'confirm'): string {
    $cancel = $self_url . list_state_qs();
    return '<section class="card confirm-card">'
         . '<h1>confirm</h1>'
         . '<p class="confirm-prompt">' . $prompt_html . '</p>'
         . '<div class="confirm-actions">'
         . '<form method="post" class="inline">'
         . csrf_field()
         . '<input type="hidden" name="action" value="' . e($action) . '">'
         . '<input type="hidden" name="id" value="' . (int)$id . '">'
         . '<button type="submit" class="danger">' . e($confirm_label) . '</button>'
         . '</form>'
         . '<a class="btn-cancel" href="' . e($cancel) . '">cancel</a>'
         . '</div>'
         . '</section>';
}

function format_duration_remaining(?string $expires_at_utc): string {
    if ($expires_at_utc === null) return 'permanent';
    $remain = strtotime($expires_at_utc . ' UTC') - time();
    if ($remain <= 0)           return 'expired';
    if ($remain < 60)           return $remain . 's';
    if ($remain < 3600)         return intdiv($remain, 60) . 'm';
    if ($remain < 86400)        return intdiv($remain, 3600) . 'h';
    if ($remain < 86400 * 30)   return intdiv($remain, 86400) . 'd';
    if ($remain < 86400 * 365)  return intdiv($remain, 86400 * 30) . 'mo';
    return intdiv($remain, 86400 * 365) . 'y';
}

/* -------------------- Timezone -------------------- */

/**
 * Curated list of timezones, grouped by region. Used in the dropdown UI.
 */
function tz_groups(): array {
    return [
        'United States' => [
            'America/New_York'    => 'Eastern (NY, DC, Atlanta)',
            'America/Chicago'     => 'Central (Chicago, Dallas, Houston)',
            'America/Denver'      => 'Mountain (Denver, Salt Lake City)',
            'America/Phoenix'     => 'Arizona (no DST)',
            'America/Los_Angeles' => 'Pacific (LA, San Francisco, Seattle)',
            'America/Anchorage'   => 'Alaska',
            'Pacific/Honolulu'    => 'Hawaii',
        ],
        'Europe' => [
            'Europe/London'    => 'UK / Ireland (GMT/BST)',
            'Europe/Paris'     => 'Western Europe (CET, Paris, Berlin, Rome, Madrid)',
            'Europe/Helsinki'  => 'Eastern Europe (EET, Helsinki, Athens, Bucharest)',
            'Europe/Istanbul'  => 'Turkey (TRT)',
        ],
        'Russia' => [
            'Europe/Kaliningrad' => 'Kaliningrad (MSK-1)',
            'Europe/Moscow'      => 'Moscow (MSK)',
            'Europe/Samara'      => 'Samara (MSK+1)',
            'Asia/Yekaterinburg' => 'Yekaterinburg (MSK+2)',
            'Asia/Omsk'          => 'Omsk (MSK+3)',
            'Asia/Krasnoyarsk'   => 'Krasnoyarsk (MSK+4)',
            'Asia/Irkutsk'       => 'Irkutsk (MSK+5)',
            'Asia/Yakutsk'       => 'Yakutsk (MSK+6)',
            'Asia/Vladivostok'   => 'Vladivostok (MSK+7)',
            'Asia/Magadan'       => 'Magadan (MSK+8)',
            'Asia/Kamchatka'     => 'Kamchatka (MSK+9)',
        ],
        'Asia' => [
            'Asia/Tokyo'   => 'Japan (JST)',
            'Asia/Kolkata' => 'India (IST)',
        ],
        'Australia' => [
            'Australia/Perth'    => 'Perth (AWST)',
            'Australia/Darwin'   => 'Darwin (ACST, no DST)',
            'Australia/Adelaide' => 'Adelaide (ACST/ACDT)',
            'Australia/Brisbane' => 'Brisbane (AEST, no DST)',
            'Australia/Sydney'   => 'Sydney, Melbourne (AEST/AEDT)',
            'Australia/Hobart'   => 'Hobart (AEST/AEDT)',
        ],
        'UTC' => [
            'UTC' => 'UTC (no offset)',
        ],
    ];
}

function tz_is_valid(string $tz): bool {
    static $set = null;
    if ($set === null) {
        $set = [];
        foreach (tz_groups() as $group) {
            foreach ($group as $tzid => $_) {
                $set[$tzid] = true;
            }
        }
    }
    return isset($set[$tz]);
}

/**
 * Resolve the timezone to use for display:
 *   1. Current user's `timezone` column if set
 *   2. settings.default_timezone if set
 *   3. PHP server default (date_default_timezone_get)
 */
function display_timezone(): string {
    static $cached = null;
    if ($cached !== null) {
        return $cached;
    }
    $u = current_user();
    if ($u && !empty($u['timezone']) && tz_is_valid($u['timezone'])) {
        return $cached = $u['timezone'];
    }
    $def = (string)setting('default_timezone', '');
    if ($def !== '' && tz_is_valid($def)) {
        return $cached = $def;
    }
    return $cached = date_default_timezone_get();
}

/**
 * Convert a 'Y-m-d H:i:s' UTC datetime string (as stored in DB) to the
 * display timezone, formatted for the UI.
 */
function format_local(?string $utc_datetime, string $fmt = 'Y-m-d H:i'): string {
    if (!$utc_datetime) return '';
    try {
        $dt = new DateTime($utc_datetime, new DateTimeZone('UTC'));
        $dt->setTimezone(new DateTimeZone(display_timezone()));
        return $dt->format($fmt);
    } catch (Exception $e) {
        return $utc_datetime;
    }
}

/**
 * Short timezone abbreviation for the current display TZ (e.g. "EDT", "JST").
 */
function tz_abbrev(): string {
    try {
        return (new DateTime('now', new DateTimeZone(display_timezone())))->format('T');
    } catch (Exception $e) {
        return 'UTC';
    }
}

/* -------------------- Audit log -------------------- */

function audit_log_write(?int $uid, ?string $username, string $action, ?string $target, ?string $details): void {
    $stmt = db()->prepare(
        'INSERT INTO audit_log (user_id, username, action, target, details, ip_address)
         VALUES (?, ?, ?, ?, ?, ?)'
    );
    $stmt->execute([$uid, $username, $action, $target, $details, client_ip()]);
}

/* -------------------- Flash messages -------------------- */

function flash(string $type, string $msg): void {
    $_SESSION['flash'][] = ['type' => $type, 'msg' => $msg];
}

function flash_render(): string {
    if (empty($_SESSION['flash'])) return '';
    $out = '';
    foreach ($_SESSION['flash'] as $f) {
        $out .= '<div class="flash flash-' . e($f['type']) . '">' . e($f['msg']) . '</div>';
    }
    unset($_SESSION['flash']);
    return $out;
}

/* -------------------- Login protection policy -------------------- */

/**
 * Single source of truth for the effective brute-force policy.
 *
 * The storage split is deliberate and preserved:
 *   - Per-IP limits are an operator hard floor in config.php. They are NOT
 *     UI-tunable on purpose: a compromised superadmin session must not be
 *     able to loosen the global brute-force floor from inside the app.
 *   - Per-account limits (lockout threshold and duration) are UI-tunable via
 *     the settings table so operators can adjust them without shell access.
 *
 * Before v0.3 these two were read ad hoc in attempt_login(), mixing
 * load_config() and setting() calls in the hot path. This accessor
 * consolidates the reads so callers see one merged, clamped policy.
 */
function login_policy(): array {
    $cfg = load_config();
    $lp  = $cfg['login_protection'] ?? [];

    return [
        // Operator hard floor (config only)
        'per_ip_max_attempts' => max(1, (int)($lp['per_ip_max_attempts'] ?? 20)),
        'per_ip_window_min'   => max(1, (int)($lp['per_ip_window_min']   ?? 15)),
        // UI-tunable per-account (settings table), clamped to sane bounds
        'max_failed_logins'   => max(1, min(20,   (int)setting('max_failed_logins', '5'))),
        'lockout_minutes'     => max(1, min(1440, (int)setting('lockout_minutes', '15'))),
    ];
}
