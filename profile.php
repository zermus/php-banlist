<?php
declare(strict_types=1);
require_once __DIR__ . '/private/auth.php';
$u = require_login();

$base = base_path();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = (string)($_POST['action'] ?? '');

    if ($action === 'set_timezone') {
        $tz = trim((string)($_POST['timezone'] ?? ''));
        if ($tz === '') {
            db()->prepare('UPDATE users SET timezone = NULL WHERE id = ?')
                ->execute([(int)$u['id']]);
            audit_log_write((int)$u['id'], $u['username'], 'self_timezone_clear', null, null);
            flash('ok', 'Timezone cleared. Using server default.');
        } elseif (tz_is_valid($tz)) {
            db()->prepare('UPDATE users SET timezone = ? WHERE id = ?')
                ->execute([$tz, (int)$u['id']]);
            audit_log_write((int)$u['id'], $u['username'], 'self_timezone_set', $tz, null);
            flash('ok', 'Timezone set to ' . $tz . '.');
        } else {
            flash('error', 'Unknown timezone.');
        }
    } elseif ($action === 'change_password') {
        $old  = (string)($_POST['old_password'] ?? '');
        $new1 = (string)($_POST['new_password'] ?? '');
        $new2 = (string)($_POST['new_password_confirm'] ?? '');

        $row = db()->prepare('SELECT password_hash FROM users WHERE id = ?');
        $row->execute([(int)$u['id']]);
        $hash = $row->fetch()['password_hash'] ?? '';

        if (!password_verify($old, $hash)) {
            flash('error', 'Current password is incorrect.');
        } elseif ($new1 !== $new2) {
            flash('error', 'New passwords do not match.');
        } elseif (($err = validate_password_policy($new1)) !== null) {
            flash('error', $err);
        } elseif (password_verify($new1, $hash)) {
            flash('error', 'New password must differ from current password.');
        } else {
            $newhash = password_hash($new1, password_algo_default());
            db()->prepare('UPDATE users SET password_hash = ? WHERE id = ?')
                ->execute([$newhash, (int)$u['id']]);
            // Changing the password invalidates persistent logins on every
            // OTHER device; the device making the change keeps its token.
            $burned = remember_revoke_others((int)$u['id']);
            audit_log_write((int)$u['id'], $u['username'], 'self_password_change', null,
                            $burned > 0 ? "revoked_remember_tokens={$burned}" : null);
            flash('ok', 'Password updated.' . ($burned > 0 ? " Signed out {$burned} other remembered device(s)." : ''));
        }
    }

    if ($action === 'revoke_device') {
        $id = (int)($_POST['id'] ?? 0);
        $row = db()->prepare('SELECT id, selector FROM remember_tokens WHERE id = ? AND user_id = ?');
        $row->execute([$id, (int)$u['id']]);
        $t = $row->fetch();
        if ($t) {
            db()->prepare('DELETE FROM remember_tokens WHERE id = ?')->execute([(int)$t['id']]);
            // If we just revoked THIS device's token, drop the cookie too so
            // the browser doesn't keep presenting a dead credential.
            if ($t['selector'] === remember_current_selector()) {
                remember_set_cookie('', time() - 42000);
            }
            audit_log_write((int)$u['id'], $u['username'], 'self_device_revoke', null, null);
            flash('ok', 'Device signed out.');
        }
    } elseif ($action === 'revoke_other_devices') {
        $burned = remember_revoke_others((int)$u['id']);
        audit_log_write((int)$u['id'], $u['username'], 'self_devices_revoke_others', null, "count={$burned}");
        flash('ok', $burned > 0 ? "Signed out {$burned} other device(s)." : 'No other devices were signed in.');
    }

    header('Location: ' . $base . '/profile.php');
    exit;
}

// JS-free revoke confirmation interstitial for remembered devices, same
// pattern as the ban/token pages.
if ($cr = confirm_request(['revoke_device'])) {
    $row = db()->prepare('SELECT id, selector, created_at FROM remember_tokens WHERE id = ? AND user_id = ?');
    $row->execute([$cr['id'], (int)$u['id']]);
    $found = $row->fetch();
    if ($found) {
        $is_this = $found['selector'] === remember_current_selector();
        $page_title = 'confirm';
        include __DIR__ . '/private/header.php';
        echo confirm_card(
            $base . '/profile.php',
            'Sign out the remembered device added <strong class="mono">'
              . e(format_local($found['created_at'])) . ' ' . e(tz_abbrev()) . '</strong>?'
              . ($is_this ? ' <strong>This is the device you are using now</strong>; you will need to log in again after your session ends.' : ''),
            'revoke_device',
            $cr['id'],
            'sign out'
        );
        include __DIR__ . '/private/footer.php';
        exit;
    }
}

// Re-read user row for fresh timezone value
$row = db()->prepare('SELECT username, role, timezone, last_login, last_login_ip FROM users WHERE id = ?');
$row->execute([(int)$u['id']]);
$me = $row->fetch();

$cfg = load_config();
$min_len = (int)($cfg['passwords']['min_length'] ?? 14);

// Remembered devices (persistent logins) for this account. Shown whenever
// any exist, even if the operator has since disabled remember_me in config,
// so stale tokens remain visible and revocable.
$dev_stmt = db()->prepare(
    'SELECT id, selector, created_at, last_used_at, expires_at
     FROM remember_tokens WHERE user_id = ? ORDER BY created_at DESC'
);
$dev_stmt->execute([(int)$u['id']]);
$devices = $dev_stmt->fetchAll();
$cur_selector = remember_current_selector();
$rc = remember_cfg();

$page_title = 'profile';
include __DIR__ . '/private/header.php';
?>
<section class="card">
  <h1>profile</h1>
  <table class="grid-table table-narrow">
    <tr><th>username</th><td class="mono"><?= e($me['username']) ?></td></tr>
    <tr><th>role</th>    <td><?= e($me['role']) ?></td></tr>
    <tr><th>timezone</th><td class="mono"><?= e($me['timezone'] ?: '(server default: ' . date_default_timezone_get() . ')') ?></td></tr>
    <tr><th>last login</th><td class="mono dim">
      <?= $me['last_login'] ? e(format_local($me['last_login'])) . ' ' . e(tz_abbrev()) : 'never' ?>
      <?php if ($me['last_login_ip']): ?> from <?= e($me['last_login_ip']) ?><?php endif; ?>
    </td></tr>
  </table>
</section>

<section class="card">
  <h2>timezone</h2>
  <form method="post" class="add-form">
    <?= csrf_field() ?>
    <input type="hidden" name="action" value="set_timezone">
    <label>my timezone
      <select name="timezone">
        <option value="">(use server default: <?= e(date_default_timezone_get()) ?>)</option>
        <?php foreach (tz_groups() as $region => $list): ?>
          <optgroup label="<?= e($region) ?>">
            <?php foreach ($list as $tzid => $disp): ?>
              <option value="<?= e($tzid) ?>" <?= ($me['timezone'] ?? '') === $tzid ? 'selected' : '' ?>>
                <?= e($tzid) ?> &mdash; <?= e($disp) ?>
              </option>
            <?php endforeach; ?>
          </optgroup>
        <?php endforeach; ?>
      </select>
      <small>all timestamps you see in the UI will use this zone</small>
    </label>
    <button type="submit">save timezone</button>
  </form>
</section>

<?php if ($devices || $rc['enabled']): ?>
<section class="card">
  <h2>remembered devices</h2>
  <p class="sub">Devices where "stay signed in" is active. Signing one out revokes its
     persistent login immediately; any live session on it still ends at the normal
     idle/absolute timeout.</p>
  <table class="grid-table table-narrow">
    <thead><tr><th>added (<?= e(tz_abbrev()) ?>)</th><th>last used</th><th>expires</th><th></th></tr></thead>
    <tbody>
    <?php foreach ($devices as $d): ?>
      <tr>
        <td class="mono dim">
          <?= e(format_local($d['created_at'])) ?>
          <?php if ($d['selector'] === $cur_selector): ?><span class="badge">this device</span><?php endif; ?>
        </td>
        <td class="mono dim"><?= e($d['last_used_at'] ? format_local($d['last_used_at']) : 'never') ?></td>
        <td class="mono dim"><?= e(format_local($d['expires_at'])) ?></td>
        <td><a class="btn-del" href="<?= e(list_state_qs(['confirm' => 'revoke_device', 'id' => (int)$d['id']])) ?>">sign out</a></td>
      </tr>
    <?php endforeach; ?>
    <?php if (!$devices): ?>
      <tr><td colspan="4" class="dim">no remembered devices</td></tr>
    <?php endif; ?>
    </tbody>
  </table>
  <?php if (count($devices) > 1 || ($devices && $cur_selector === null)): ?>
  <form method="post" class="inline">
    <?= csrf_field() ?>
    <input type="hidden" name="action" value="revoke_other_devices">
    <button type="submit" class="danger">sign out all other devices</button>
  </form>
  <?php endif; ?>
</section>
<?php endif; ?>

<section class="card">
  <h2>change password</h2>
  <form method="post" class="add-form" autocomplete="off">
    <?= csrf_field() ?>
    <input type="hidden" name="action" value="change_password">
    <label>current password
      <input type="password" name="old_password" required maxlength="256">
    </label>
    <label>new password
      <input type="password" name="new_password" required
             minlength="<?= (int)$min_len ?>" maxlength="256">
    </label>
    <label>confirm new password
      <input type="password" name="new_password_confirm" required
             minlength="<?= (int)$min_len ?>" maxlength="256">
    </label>
    <button type="submit">change password</button>
  </form>
</section>
<?php include __DIR__ . '/private/footer.php'; ?>
