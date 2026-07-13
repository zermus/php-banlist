<?php
/**
 * Write API: add / remove bans over HTTP with an API token.
 *
 * Off by default. Two switches must BOTH be on before any write happens:
 *   1. settings.enable_write_api = 1  (settings page, superadmin)
 *   2. the token's can_write flag     (tokens page, per token)
 * Existing feed tokens are read-only until explicitly upgraded, so enabling
 * the API never silently grants write access to already-issued credentials.
 *
 * Auth is the API token ONLY (X-API-Token header or token= param). Sessions
 * and cookies are deliberately never consulted here, so the endpoint cannot
 * be driven cross-site by a logged-in browser: no cookie auth means CSRF
 * does not apply. No CORS headers are emitted either (deny by default).
 *
 * Requests: POST, form-encoded or JSON body.
 *   action   = add | remove          (required)
 *   type     = ip | fqdn             (required; token scope must cover it)
 *   value    = entry, or several separated by newlines/commas (required)
 *   reason   = free text, add only   (optional, <=255 chars)
 *   duration = 30m 2h 7d 1mo 1y p    (optional, add only; blank = default)
 *
 * Responses: JSON. 200 on success, 400/401/403/405 otherwise.
 *   add:    {"ok":true,"added":N,"invalid":[...]}
 *   remove: {"ok":true,"removed":N,"not_found":[...],"invalid":[...]}
 *
 * Examples (curl):
 *   curl -X POST -H 'X-API-Token: TOKEN' \
 *        -d 'action=add&type=ip&value=203.0.113.5&reason=ssh scans&duration=7d' \
 *        https://host/php-banlist/api.php
 *   curl -X POST -H 'X-API-Token: TOKEN' \
 *        -d 'action=remove&type=fqdn&value=bad.example.com' \
 *        https://host/php-banlist/api.php
 */
declare(strict_types=1);
require_once __DIR__ . '/private/db.php';
require_once __DIR__ . '/private/functions.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');

function api_out(int $status, array $body): void {
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_SLASHES) . "\n";
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    api_out(405, ['ok' => false, 'error' => 'POST only']);
}

// Global switch (settings page, superadmin only)
if ((int)setting('enable_write_api', '0') !== 1) {
    api_out(403, ['ok' => false, 'error' => 'write api disabled']);
}

// Optional source-IP ACL, separate from the feed ACL. Empty = allow any.
$acl = load_config()['api_acl'] ?? [];
if ($acl) {
    $caller = client_ip();
    $ok = false;
    foreach ($acl as $cidr) {
        if (ip_in_cidr($caller, $cidr)) { $ok = true; break; }
    }
    if (!$ok) {
        api_out(403, ['ok' => false, 'error' => 'source ip not allowed']);
    }
}

// Accept a JSON body as an alternative to form-encoding.
$in = $_POST;
$ctype = strtolower((string)($_SERVER['CONTENT_TYPE'] ?? ''));
if (strpos($ctype, 'application/json') !== false) {
    $decoded = json_decode((string)file_get_contents('php://input'), true);
    if (!is_array($decoded)) {
        api_out(400, ['ok' => false, 'error' => 'invalid json body']);
    }
    $in = $decoded;
}

// Token auth. Header preferred; token= param accepted for parity with the
// feeds (but the header keeps the secret out of access logs).
$tok = (string)($_SERVER['HTTP_X_API_TOKEN'] ?? $in['token'] ?? '');
if ($tok === '' || strlen($tok) > 128) {
    api_out(401, ['ok' => false, 'error' => 'token required']);
}
$stmt = db()->prepare(
    'SELECT id, label, list_type, can_write, created_by FROM api_tokens WHERE token_hash = ?'
);
$stmt->execute([hash('sha256', $tok)]);
$token = $stmt->fetch();
if (!$token) {
    api_out(403, ['ok' => false, 'error' => 'token rejected']);
}
db()->prepare('UPDATE api_tokens SET last_used_at = UTC_TIMESTAMP() WHERE id = ?')
    ->execute([(int)$token['id']]);

if ((int)$token['can_write'] !== 1) {
    api_out(403, ['ok' => false, 'error' => 'token is read-only']);
}

// Validate request shape
$action = (string)($in['action'] ?? '');
$type   = (string)($in['type'] ?? '');
$raw    = (string)($in['value'] ?? '');

if (!in_array($action, ['add', 'remove'], true)) {
    api_out(400, ['ok' => false, 'error' => 'action must be add or remove']);
}
if ($type !== 'ip' && $type !== 'fqdn') {
    api_out(400, ['ok' => false, 'error' => 'type must be ip or fqdn']);
}
if ($token['list_type'] !== 'both' && $token['list_type'] !== $type) {
    api_out(403, ['ok' => false, 'error' => "token not scoped for {$type}"]);
}
if (trim($raw) === '') {
    api_out(400, ['ok' => false, 'error' => 'value required']);
}

// Same multi-entry splitting as the UI add forms.
$lines = preg_split('/[\r\n,]+/', $raw) ?: [];
$normalize = $type === 'ip' ? 'normalize_ip_or_cidr' : 'normalize_hostname';
$table     = $type === 'ip' ? 'ip_bans'  : 'fqdn_bans';
$column    = $type === 'ip' ? 'ip_address' : 'fqdn';

// Bans created via the API are attributed to the user who issued the token
// (created_by is a NOT NULL FK); the audit trail records the token label.
$actor_uid = (int)$token['created_by'];
$actor     = 'token:' . $token['label'];

if ($action === 'add') {
    $reason = trim((string)($in['reason'] ?? ''));
    if (strlen($reason) > 255) {
        api_out(400, ['ok' => false, 'error' => 'reason too long (max 255)']);
    }
    $dur_in = trim((string)($in['duration'] ?? ''));
    if ($dur_in === '') {
        // Blank duration follows the same system default as the UI.
        $default_to = (int)setting('default_timeout_seconds', '0');
        $duration = $default_to === 0
            ? ['expires_at' => null, 'permanent' => true]
            : ['expires_at' => gmdate('Y-m-d H:i:s', time() + $default_to), 'permanent' => false];
    } else {
        $duration = parse_duration($dur_in);
        if ($duration === null) {
            api_out(400, ['ok' => false, 'error' => 'bad duration; use 30m 2h 7d 1mo 1y p']);
        }
    }
    $exp = $duration['permanent'] ? null : $duration['expires_at'];

    $stmt = db()->prepare(
        "INSERT INTO {$table} ({$column}, reason, created_by, expires_at)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE reason = VALUES(reason),
                                 created_by = VALUES(created_by),
                                 expires_at = VALUES(expires_at)"
    );

    $added = 0; $bad = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        $norm = $normalize($line);
        if ($norm === null) {
            $bad[] = $line;
            continue;
        }
        $stmt->execute([$norm, $reason !== '' ? $reason : null, $actor_uid, $exp]);
        $added++;
        audit_log_write($actor_uid, $actor, "api_{$type}_ban_add", $norm,
                        $exp ? "expires={$exp}" : 'permanent');
    }
    api_out(200, ['ok' => true, 'added' => $added, 'invalid' => array_slice($bad, 0, 20)]);
}

// action === 'remove'
$del = db()->prepare("DELETE FROM {$table} WHERE {$column} = ?");
$removed = 0; $missing = []; $bad = [];
foreach ($lines as $line) {
    $line = trim($line);
    if ($line === '' || $line[0] === '#') continue;
    $norm = $normalize($line);
    if ($norm === null) {
        $bad[] = $line;
        continue;
    }
    $del->execute([$norm]);
    if ($del->rowCount() > 0) {
        $removed++;
        audit_log_write($actor_uid, $actor, "api_{$type}_ban_del", $norm, null);
    } else {
        $missing[] = $norm;
    }
}
api_out(200, [
    'ok'        => true,
    'removed'   => $removed,
    'not_found' => array_slice($missing, 0, 20),
    'invalid'   => array_slice($bad, 0, 20),
]);
