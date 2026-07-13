<?php
declare(strict_types=1);
require_once __DIR__ . '/private/auth.php';
session_boot();

// config loaded lazily
$base = base_path();

// Already logged in
if (current_user()) {
    header('Location: ' . $base . '/');
    exit;
}

$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $u = trim((string)($_POST['username'] ?? ''));
    $p = (string)($_POST['password'] ?? '');
    $remember = !empty($_POST['remember']);
    if ($u === '' || $p === '') {
        $error = 'Username and password required.';
    } elseif (attempt_login($u, $p, $remember)) {
        // Build a safe redirect: only same-app paths allowed
        $next = (string)($_GET['next'] ?? $base . '/');
        if (!preg_match('~^' . preg_quote($base, '~') . '/[^/]~', $next)) {
            $next = $base . '/';
        }
        header('Location: ' . $next);
        exit;
    } else {
        // Deliberately vague to avoid username enumeration
        $error = 'Invalid credentials or account temporarily locked.';
        usleep(random_int(150000, 400000));
    }
}

$page_title = 'login';
include __DIR__ . '/private/header.php';
?>
<section class="card login-card">
  <h1>auth required</h1>
  <?php if ($error): ?><div class="flash flash-error"><?= e($error) ?></div><?php endif; ?>
  <form method="post" autocomplete="off" novalidate>
    <?= csrf_field() ?>
    <label>username
      <input type="text" name="username" required autofocus
             autocapitalize="off" autocorrect="off" spellcheck="false"
             maxlength="64" pattern="[A-Za-z0-9_.\-]+">
    </label>
    <label>password
      <input type="password" name="password" required maxlength="256">
    </label>
    <?php $rc = remember_cfg(); if ($rc['enabled']): ?>
    <label class="remember">
      <input type="checkbox" name="remember" value="1">
      stay signed in on this device for <?= (int)$rc['days'] ?> days
    </label>
    <?php endif; ?>
    <button type="submit">login</button>
  </form>
</section>
<?php include __DIR__ . '/private/footer.php'; ?>
