<?php
/**
 * Layout header. Set $page_title before including.
 */
declare(strict_types=1);

$cfg  = load_config();
$base = base_path();

// Security response headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
header(
    "Content-Security-Policy: " .
    "default-src 'none'; " .
    "base-uri 'self'; " .
    "form-action 'self'; " .
    "frame-ancestors 'none'; " .
    "img-src 'self' data:; " .
    "style-src 'self'; " .
    "font-src 'self'; " .
    "connect-src 'self';"
);
if (is_https()) {
    header("Strict-Transport-Security: max-age=63072000; includeSubDomains");
}

$u = current_user();
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= e($page_title ?? 'php-banlist') ?> :: <?= e($cfg['site']['name']) ?></title>
<link rel="stylesheet" href="<?= e($base) ?>/assets/style.css">
</head>
<body>
<header class="topbar">
  <div class="brand">
    <span class="prompt">root@banlist:~#</span>
    <a href="<?= e($base) ?>/"><?= e($cfg['site']['name']) ?></a>
  </div>
  <?php if ($u): ?>
  <nav class="nav">
    <a href="<?= e($base) ?>/">dash</a>
    <a href="<?= e($base) ?>/ip-bans.php">ip</a>
    <a href="<?= e($base) ?>/fqdn-bans.php">fqdn</a>
    <a href="<?= e($base) ?>/audit.php">audit</a>
    <?php if (role_can_admin_users($u)): ?>
      <a href="<?= e($base) ?>/users.php">users</a>
      <a href="<?= e($base) ?>/settings.php">settings</a>
      <a href="<?= e($base) ?>/tokens.php">tokens</a>
    <?php endif; ?>
    <a href="<?= e($base) ?>/profile.php" class="who"><?= e($u['username']) ?>@<?= e($u['role']) ?></a>
    <a class="logout" href="<?= e($base) ?>/logout.php">logout</a>
  </nav>
  <?php endif; ?>
</header>
<main class="main">
<?= flash_render() ?>
