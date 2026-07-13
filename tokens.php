<?php
declare(strict_types=1);
require_once __DIR__ . '/private/auth.php';
$u = require_role('superadmin');

// config loaded lazily
$base = base_path();

$new_token = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = (string)($_POST['action'] ?? '');

    if ($action === 'create') {
        $label = trim((string)($_POST['label'] ?? ''));
        $type  = (string)($_POST['list_type'] ?? 'both');
        $write = !empty($_POST['can_write']) ? 1 : 0;
        if ($label === '' || !preg_match('/^[A-Za-z0-9_.\- ]{1,64}$/', $label)) {
            flash('error', 'Label: 1-64 chars [A-Za-z0-9_.- ]');
        } elseif (!in_array($type, ['ip','fqdn','both'], true)) {
            flash('error', 'Invalid list type.');
        } else {
            $token = bin2hex(random_bytes(24));
            $hash  = hash('sha256', $token);
            db()->prepare('INSERT INTO api_tokens (label, token_hash, list_type, can_write, created_by) VALUES (?, ?, ?, ?, ?)')
                ->execute([$label, $hash, $type, $write, (int)$u['id']]);
            audit_log_write((int)$u['id'], $u['username'], 'token_create', $label, "type={$type} write={$write}");
            $new_token = $token; // shown once
            flash('ok', 'Token created. Save it now: it is not stored in plaintext.');
        }
    } elseif ($action === 'delete') {
        $id = (int)($_POST['id'] ?? 0);
        $row = db()->prepare('SELECT label FROM api_tokens WHERE id = ?');
        $row->execute([$id]);
        $t = $row->fetch();
        if ($t) {
            db()->prepare('DELETE FROM api_tokens WHERE id = ?')->execute([$id]);
            audit_log_write((int)$u['id'], $u['username'], 'token_delete', $t['label'], null);
            flash('ok', 'Token revoked.');
        }
    }

    if (!$new_token) {
        header('Location: ' . $base . '/tokens.php');
        exit;
    }
}

// JS-free revoke confirmation interstitial (replaces the dead inline
// onsubmit="confirm()" handler, which never fired under the strict CSP).
if ($cr = confirm_request(['delete'])) {
    $row = db()->prepare('SELECT label FROM api_tokens WHERE id = ?');
    $row->execute([$cr['id']]);
    $found = $row->fetch();
    if ($found) {
        $page_title = 'confirm';
        include __DIR__ . '/private/header.php';
        echo confirm_card(
            $base . '/tokens.php',
            'Revoke token <strong class="mono">' . e($found['label']) . '</strong>? Any client using it will lose access immediately.',
            'delete',
            $cr['id'],
            'revoke'
        );
        include __DIR__ . '/private/footer.php';
        exit;
    }
}

$rows = db()->query(
    'SELECT id, label, list_type, can_write, last_used_at, created_at FROM api_tokens ORDER BY created_at DESC'
)->fetchAll();

$write_api_on = (int)setting('enable_write_api', '0') === 1;

$page_title = 'tokens';
include __DIR__ . '/private/header.php';
?>
<section class="card">
  <h1>api tokens</h1>
  <p class="sub">Used when "require token for lists" is enabled in settings, and for the write API
     (<code>api.php</code>). Pass as <code>?token=...</code> or <code>X-API-Token</code> header.
     Write access needs BOTH the per-token flag below and the global switch in settings
     (currently <?= $write_api_on ? 'enabled' : 'disabled' ?>).</p>

  <?php if ($new_token): ?>
    <div class="flash flash-warn">
      New token (shown once):
      <pre class="mono token-show"><?= e($new_token) ?></pre>
    </div>
  <?php endif; ?>

  <form method="post" class="add-form">
    <?= csrf_field() ?>
    <input type="hidden" name="action" value="create">
    <label>label
      <input type="text" name="label" required maxlength="64"
             pattern="[A-Za-z0-9_.\- ]+" placeholder="e.g. junon-pfsense">
    </label>
    <label>list access
      <select name="list_type">
        <option value="both">both</option>
        <option value="ip">ip only</option>
        <option value="fqdn">fqdn only</option>
      </select>
    </label>
    <label class="checkbox-inline">
      <input type="checkbox" name="can_write" value="1">
      allow write (add/remove bans via api.php)
    </label>
    <button type="submit">issue token</button>
  </form>
</section>

<section class="card">
  <table class="grid-table">
    <thead><tr><th>label</th><th>access</th><th>write</th><th>last used (<?= e(tz_abbrev()) ?>)</th><th>created (<?= e(tz_abbrev()) ?>)</th><th></th></tr></thead>
    <tbody>
    <?php foreach ($rows as $r): ?>
      <tr>
        <td class="mono"><?= e($r['label']) ?></td>
        <td><?= e($r['list_type']) ?></td>
        <td class="mono"><?= (int)$r['can_write'] === 1 ? 'yes' : '<span class="dim">no</span>' ?></td>
        <td class="mono dim"><?= e($r['last_used_at'] ? format_local($r['last_used_at'], 'Y-m-d H:i:s') : 'never') ?></td>
        <td class="mono dim"><?= e(format_local($r['created_at'], 'Y-m-d H:i:s')) ?></td>
        <td>
          <a class="btn-del" href="<?= e(confirm_link('delete', (int)$r['id'])) ?>">revoke</a>
        </td>
      </tr>
    <?php endforeach; ?>
    <?php if (!$rows): ?>
      <tr><td colspan="6" class="dim">no tokens</td></tr>
    <?php endif; ?>
    </tbody>
  </table>
</section>
<?php include __DIR__ . '/private/footer.php'; ?>
