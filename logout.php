<?php
declare(strict_types=1);
require_once __DIR__ . '/private/auth.php';
session_boot();

// Logout is a state change: POST + CSRF only. A bare GET (bookmark, forced
// navigation, <img src=...> from another origin) must not end the session.
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Location: ' . base_path() . '/', true, 303);
    exit;
}
csrf_check();

$u = current_user();
if ($u) {
    audit_log_write((int)$u['id'], $u['username'], 'logout', null, null);
}
remember_clear();
session_destroy_full();
// config loaded lazily
header('Location: ' . base_path() . '/login.php', true, 303);
