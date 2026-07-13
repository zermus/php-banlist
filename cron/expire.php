<?php
/**
 * Hard-delete expired bans, prune login_attempts and audit_log to their
 * configured retention windows, and drop expired remember-me tokens.
 *
 * Retention windows are read from config.php ('retention' block); they
 * default to 30 days (login_attempts) and 365 days (audit_log) when unset.
 *
 * Recommended cron (run as web user or a dedicated user with DB access):
 *   See INSTALL.txt for the crontab line (slash-star sequences cannot
 *   appear inside a PHPDoc block).
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("CLI only.\n");
}

require_once __DIR__ . '/../private/db.php';

$cfg = load_config();
$ret = $cfg['retention'] ?? [];
$la_days = max(1, (int)($ret['login_attempts_days'] ?? 30));
$al_days = max(1, (int)($ret['audit_log_days'] ?? 365));

$pdo = db();

$ip   = $pdo->exec('DELETE FROM ip_bans   WHERE expires_at IS NOT NULL AND expires_at < UTC_TIMESTAMP()');
$fqdn = $pdo->exec('DELETE FROM fqdn_bans WHERE expires_at IS NOT NULL AND expires_at < UTC_TIMESTAMP()');

$la_stmt = $pdo->prepare('DELETE FROM login_attempts WHERE attempted_at < (UTC_TIMESTAMP() - INTERVAL ? DAY)');
$la_stmt->execute([$la_days]);
$la = $la_stmt->rowCount();

$al_stmt = $pdo->prepare('DELETE FROM audit_log WHERE created_at < (UTC_TIMESTAMP() - INTERVAL ? DAY)');
$al_stmt->execute([$al_days]);
$al = $al_stmt->rowCount();

// Expired persistent-login tokens (table absent on pre-0.3 schemas: ignore).
$rt = 0;
try {
    $rt = $pdo->exec('DELETE FROM remember_tokens WHERE expires_at < UTC_TIMESTAMP()');
} catch (PDOException $e) {
    $rt = 0;
}

printf("[%s UTC] expired ip=%d fqdn=%d, pruned login_attempts=%d audit_log=%d remember_tokens=%d\n",
    gmdate('Y-m-d H:i:s'), (int)$ip, (int)$fqdn, (int)$la, (int)$al, (int)$rt);
