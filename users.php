<?php
declare(strict_types=1);
require_once __DIR__ . '/private/auth.php';
$u = require_role('superadmin');

// config loaded lazily
$base = base_path();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = (string)($_POST['action'] ?? '');

    if ($action === 'create') {
        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');
        $role     = (string)($_POST['role'] ?? 'readonly');

        if (!preg_match('/^[A-Za-z0-9_.\-]{2,64}$/', $username)) {
            flash('error', 'Username: 2-64 chars [A-Za-z0-9_.-]');
        } elseif (!in_array($role, ['readonly','admin','superadmin'], true)) {
            flash('error', 'Invalid role.');
        } elseif (($err = validate_password_policy($password)) !== null) {
            flash('error', $err);
        } else {
            try {
                $hash = password_hash($password, password_algo_default());
                db()->prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
                    ->execute([$username, $hash, $role]);
                audit_log_write((int)$u['id'], $u['username'], 'user_create', $username, "role={$role}");
                flash('ok', "Created {$username} as {$role}.");
            } catch (PDOException $e) {
                if (($e->errorInfo[1] ?? null) === 1062) {
                    flash('error', 'Username already exists.');
                } else {
                    flash('error', 'DB error.');
                }
            }
        }

    } elseif ($action === 'delete') {
        $id = (int)($_POST['id'] ?? 0);
        if ($id === (int)$u['id']) {
            flash('error', 'Cannot delete your own account.');
        } else {
            // Don't delete the last superadmin
            $cnt = (int)db()->query("SELECT COUNT(*) c FROM users WHERE role='superadmin'")->fetch()['c'];
            $row = db()->prepare('SELECT username, role FROM users WHERE id = ?');
            $row->execute([$id]);
            $target = $row->fetch();
            if (!$target) {
                flash('error', 'User not found.');
            } elseif ($target['role'] === 'superadmin' && $cnt <= 1) {
                flash('error', 'Refusing to delete the last superadmin.');
            } else {
                try {
                    db()->prepare('DELETE FROM users WHERE id = ?')->execute([$id]);
                    audit_log_write((int)$u['id'], $u['username'], 'user_delete', $target['username'], null);
                    flash('ok', 'Deleted ' . $target['username']);
                } catch (PDOException $e) {
                    // FK on ip_bans.created_by / fqdn_bans.created_by uses RESTRICT.
                    flash('error', 'Cannot delete: user has existing bans. Reassign or remove them first.');
                }
            }
        }

    } elseif ($action === 'set_role') {
        $id   = (int)($_POST['id'] ?? 0);
        $role = (string)($_POST['role'] ?? '');
        if (!in_array($role, ['readonly','admin','superadmin'], true)) {
            flash('error', 'Invalid role.');
        } elseif ($id === (int)$u['id'] && $role !== 'superadmin') {
            flash('error', 'Cannot demote your own account.');
        } else {
            $cnt = (int)db()->query("SELECT COUNT(*) c FROM users WHERE role='superadmin'")->fetch()['c'];
            $row = db()->prepare('SELECT username, role FROM users WHERE id = ?');
            $row->execute([$id]);
            $target = $row->fetch();
            if ($target && $target['role'] === 'superadmin' && $role !== 'superadmin' && $cnt <= 1) {
                flash('error', 'Refusing to demote the last superadmin.');
            } elseif ($target) {
                db()->prepare('UPDATE users SET role = ? WHERE id = ?')->execute([$role, $id]);
                audit_log_write((int)$u['id'], $u['username'], 'user_set_role', $target['username'], "role={$role}");
                flash('ok', $target['username'] . ' -> ' . $role);
            }
        }

    } elseif ($action === 'reset_password') {
        $id = (int)($_POST['id'] ?? 0);
        $pw = (string)($_POST['password'] ?? '');
        if (($err = validate_password_policy($pw)) !== null) {
            flash('error', $err);
        } else {
            $row = db()->prepare('SELECT username FROM users WHERE id = ?');
            $row->execute([$id]);
            $t = $row->fetch();
            if ($t) {
                $hash = password_hash($pw, password_algo_default());
                db()->prepare('UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?')
                    ->execute([$hash, $id]);
                // An admin-side reset implies the old credential can no
                // longer be trusted: burn ALL of the user's persistent
                // logins (unlike a self-service change, no device is spared).
                $rt = db()->prepare('DELETE FROM remember_tokens WHERE user_id = ?');
                $rt->execute([$id]);
                $burned = $rt->rowCount();
                audit_log_write((int)$u['id'], $u['username'], 'user_password_reset', $t['username'],
                                $burned > 0 ? "revoked_remember_tokens={$burned}" : null);
                flash('ok', 'Password reset for ' . $t['username']);
            }
        }

    } elseif ($action === 'unlock') {
        $id = (int)($_POST['id'] ?? 0);
        $row = db()->prepare('SELECT username FROM users WHERE id = ?');
        $row->execute([$id]);
        $t = $row->fetch();
        if ($t) {
            db()->prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?')->execute([$id]);
            audit_log_write((int)$u['id'], $u['username'], 'user_unlock', $t['username'], null);
            flash('ok', 'Unlocked ' . $t['username']);
        }
    }

    header('Location: ' . $base . '/users.php');
    exit;
}

// JS-free delete confirmation interstitial (replaces the dead inline
// onsubmit="confirm()" handler). The destructive guards (self-delete,
// last-superadmin) still fire on the POST below.
if ($cr = confirm_request(['delete'])) {
    $row = db()->prepare('SELECT username FROM users WHERE id = ?');
    $row->execute([$cr['id']]);
    $found = $row->fetch();
    if ($found && (int)$cr['id'] !== (int)$u['id']) {
        $page_title = 'confirm';
        include __DIR__ . '/private/header.php';
        echo confirm_card(
            $base . '/users.php',
            'Delete user <strong class="mono">' . e($found['username']) . '</strong>? This cannot be undone.',
            'delete',
            $cr['id'],
            'del'
        );
        include __DIR__ . '/private/footer.php';
        exit;
    }
}

$users = db()->query(
    'SELECT id, username, role, failed_attempts, locked_until, last_login, last_login_ip, created_at
     FROM users ORDER BY username'
)->fetchAll();

$page_title = 'users';
include __DIR__ . '/private/header.php';
?>
<section class="card">
  <h1>create user</h1>
  <form method="post" class="add-form" autocomplete="off">
    <?= csrf_field() ?>
    <input type="hidden" name="action" value="create">
    <label>username
      <input type="text" name="username" required maxlength="64" pattern="[A-Za-z0-9_.\-]{2,64}">
    </label>
    <label>password
      <input type="password" name="password" required minlength="14">
    </label>
    <label>role
      <select name="role">
        <option value="readonly">readonly</option>
        <option value="admin">admin</option>
        <option value="superadmin">superadmin</option>
      </select>
    </label>
    <button type="submit">create</button>
  </form>
</section>

<section class="card">
  <h2>users</h2>
  <table class="grid-table">
    <thead><tr>
      <th>username</th><th>role</th><th>last login</th><th>locked</th><th>actions</th>
    </tr></thead>
    <tbody>
    <?php foreach ($users as $row): ?>
      <tr>
        <td class="mono"><?= e($row['username']) ?></td>
        <td>
          <form method="post" class="inline">
            <?= csrf_field() ?>
            <input type="hidden" name="action" value="set_role">
            <input type="hidden" name="id" value="<?= (int)$row['id'] ?>">
            <select name="role">
              <?php foreach (['readonly','admin','superadmin'] as $r): ?>
                <option value="<?= e($r) ?>" <?= $r === $row['role'] ? 'selected' : '' ?>><?= e($r) ?></option>
              <?php endforeach; ?>
            </select>
            <button type="submit">set</button>
          </form>
        </td>
        <td class="mono dim">
          <?= $row['last_login'] ? e(format_local($row['last_login'])) : 'never' ?>
          <?php if ($row['last_login_ip']): ?><br><?= e($row['last_login_ip']) ?><?php endif; ?>
        </td>
        <td><?= $row['locked_until'] && strtotime($row['locked_until']) > time() ? 'yes' : 'no' ?></td>
        <td class="actions">
          <form method="post" class="inline">
            <?= csrf_field() ?>
            <input type="hidden" name="action" value="reset_password">
            <input type="hidden" name="id" value="<?= (int)$row['id'] ?>">
            <input type="password" name="password" placeholder="new password" minlength="14">
            <button type="submit">reset pw</button>
          </form>
          <form method="post" class="inline">
            <?= csrf_field() ?>
            <input type="hidden" name="action" value="unlock">
            <input type="hidden" name="id" value="<?= (int)$row['id'] ?>">
            <button type="submit">unlock</button>
          </form>
          <?php if ((int)$row['id'] !== (int)$u['id']): ?>
          <a class="btn-del" href="<?= e(confirm_link('delete', (int)$row['id'])) ?>">del</a>
          <?php endif; ?>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</section>
<?php include __DIR__ . '/private/footer.php'; ?>
