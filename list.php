<?php
/**
 * Public list emitter. Output is text/plain, one entry per line.
 * Reached via rewrite from /IP-list.txt and /FQDN-list.txt.
 */
declare(strict_types=1);
require_once __DIR__ . '/private/db.php';
require_once __DIR__ . '/private/functions.php';

// config loaded lazily
$type = (string)($_GET['type'] ?? '');
if ($type !== 'ip' && $type !== 'fqdn') {
    http_response_code(404);
    exit;
}

// Optional source-IP ACL
$acl = load_config()['list_acl'] ?? [];
if ($acl) {
    $caller = client_ip();
    $ok = false;
    foreach ($acl as $cidr) {
        if (ip_in_cidr($caller, $cidr)) { $ok = true; break; }
    }
    if (!$ok) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo "# 403: source IP not allowed\n";
        exit;
    }
}

// Optional token requirement
if ((int)setting('require_token_for_lists', '0') === 1) {
    $tok = (string)($_GET['token'] ?? $_SERVER['HTTP_X_API_TOKEN'] ?? '');
    if ($tok === '' || strlen($tok) > 128) {
        http_response_code(401);
        header('Content-Type: text/plain; charset=utf-8');
        echo "# 401: token required\n";
        exit;
    }
    $hash = hash('sha256', $tok);
    $stmt = db()->prepare('SELECT id, list_type FROM api_tokens WHERE token_hash = ?');
    $stmt->execute([$hash]);
    $t = $stmt->fetch();
    $allowed = $t && ($t['list_type'] === 'both' || $t['list_type'] === $type);
    if (!$allowed) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo "# 403: token rejected\n";
        exit;
    }
    db()->prepare('UPDATE api_tokens SET last_used_at = UTC_TIMESTAMP() WHERE id = ?')
        ->execute([(int)$t['id']]);
}

// Emit
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');

if ($type === 'ip') {
    $stmt = db()->query(
        'SELECT ip_address FROM ip_bans
         WHERE expires_at IS NULL OR expires_at > UTC_TIMESTAMP()
         ORDER BY ip_address'
    );
    echo "# php-banlist v" . PBL_VERSION . " ip list, generated " . gmdate('c') . "\n";
    while (($row = $stmt->fetch(PDO::FETCH_ASSOC))) {
        // Defense in depth: re-validate before emitting
        $v = normalize_ip_or_cidr($row['ip_address']);
        if ($v !== null) {
            echo $v . "\n";
        }
    }
} else {
    $stmt = db()->query(
        'SELECT fqdn FROM fqdn_bans
         WHERE expires_at IS NULL OR expires_at > UTC_TIMESTAMP()
         ORDER BY fqdn'
    );
    echo "# php-banlist v" . PBL_VERSION . " fqdn list, generated " . gmdate('c') . "\n";
    while (($row = $stmt->fetch(PDO::FETCH_ASSOC))) {
        $v = normalize_hostname($row['fqdn']);
        if ($v !== null) {
            echo $v . "\n";
        }
    }
}
