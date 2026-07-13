<?php
declare(strict_types=1);
require_once __DIR__ . '/private/auth.php';
session_boot();
$u = current_user();
if ($u) {
    audit_log_write((int)$u['id'], $u['username'], 'logout', null, null);
}
remember_clear();
session_destroy_full();
// config loaded lazily
header('Location: ' . base_path() . '/login.php');
