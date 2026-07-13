<?php
declare(strict_types=1);
require_once __DIR__ . '/private/auth.php';
$u = require_login();

// config loaded lazily
$base = base_path();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    if (!role_can_write($u)) {
        flash('error', 'Read-only account cannot modify the list.');
        header('Location: ' . $base . '/fqdn-bans.php' . list_state_qs());
        exit;
    }
    $action = (string)($_POST['action'] ?? '');
    if ($action === 'add') {
        $raw     = (string)($_POST['fqdn'] ?? '');
        $reason  = trim((string)($_POST['reason'] ?? ''));
        $dur_in  = (string)($_POST['duration'] ?? '');

        $lines   = preg_split('/[\r\n,]+/', $raw) ?: [];
        $added = 0; $bad = [];

        $default_to = (int)setting('default_timeout_seconds', '0');
        if ($dur_in === '') {
            if ($default_to === 0) {
                $duration = ['seconds' => null, 'expires_at' => null, 'permanent' => true];
            } else {
                $duration = [
                    'seconds'    => $default_to,
                    'expires_at' => gmdate('Y-m-d H:i:s', time() + $default_to),
                    'permanent'  => false,
                ];
            }
        } else {
            $duration = parse_duration($dur_in);
            if ($duration === null) {
                flash('error', 'Bad duration. Use 30m, 2h, 7d, 1mo, 1y, or p.');
                header('Location: ' . $base . '/fqdn-bans.php' . list_state_qs());
                exit;
            }
        }

        $stmt = db()->prepare(
            'INSERT INTO fqdn_bans (fqdn, reason, created_by, expires_at)
             VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE reason = VALUES(reason),
                                     created_by = VALUES(created_by),
                                     expires_at = VALUES(expires_at)'
        );

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') continue;
            $norm = normalize_hostname($line);
            if ($norm === null) {
                $bad[] = $line;
                continue;
            }
            $exp = $duration['permanent'] ? null : $duration['expires_at'];
            $stmt->execute([$norm, $reason !== '' ? $reason : null, (int)$u['id'], $exp]);
            $added++;
            audit_log_write((int)$u['id'], $u['username'], 'fqdn_ban_add', $norm,
                            $exp ? "expires={$exp}" : 'permanent');
        }

        $msg = "added {$added}";
        if ($bad) $msg .= ', ' . count($bad) . ' invalid: ' . e(implode(' ', array_slice($bad, 0, 5)));
        flash($bad ? 'warn' : 'ok', $msg);

    } elseif ($action === 'delete') {
        $id = (int)($_POST['id'] ?? 0);
        $row = db()->prepare('SELECT fqdn FROM fqdn_bans WHERE id = ?');
        $row->execute([$id]);
        $found = $row->fetch();
        if ($found) {
            db()->prepare('DELETE FROM fqdn_bans WHERE id = ?')->execute([$id]);
            audit_log_write((int)$u['id'], $u['username'], 'fqdn_ban_del', $found['fqdn'], null);
            flash('ok', 'Removed ' . $found['fqdn']);
        }
    } elseif ($action === 'extend') {
        $id  = (int)($_POST['id'] ?? 0);
        $dur = parse_duration((string)($_POST['extend'] ?? ''));
        if ($dur === null) {
            flash('error', 'Bad duration.');
        } else {
            if ($dur['permanent']) {
                db()->prepare('UPDATE fqdn_bans SET expires_at = NULL WHERE id = ?')->execute([$id]);
                flash('ok', 'Set permanent.');
            } else {
                $exp = $dur['expires_at'];
                db()->prepare('UPDATE fqdn_bans SET expires_at = ? WHERE id = ?')->execute([$exp, $id]);
                flash('ok', 'New expiry ' . format_local($exp) . ' ' . tz_abbrev());
            }
            audit_log_write((int)$u['id'], $u['username'], 'fqdn_ban_extend', (string)$id, null);
        }
    }
    header('Location: ' . $base . '/fqdn-bans.php' . list_state_qs());
    exit;
}

// JS-free delete confirmation interstitial (replaces the dead inline
// onsubmit="confirm()" handler, which never fired under the strict CSP).
if (role_can_write($u) && ($cr = confirm_request(['delete']))) {
    $row = db()->prepare('SELECT fqdn FROM fqdn_bans WHERE id = ?');
    $row->execute([$cr['id']]);
    $found = $row->fetch();
    if ($found) {
        $page_title = 'confirm';
        include __DIR__ . '/private/header.php';
        echo confirm_card(
            $base . '/fqdn-bans.php',
            'Remove ban on <strong class="mono">' . e($found['fqdn']) . '</strong>?',
            'delete',
            $cr['id'],
            'del'
        );
        include __DIR__ . '/private/footer.php';
        exit;
    }
}

$q = trim((string)($_GET['q'] ?? ''));
$show_expired = !empty($_GET['expired']);

$where = ' WHERE 1=1';
$params = [];
if (!$show_expired) {
    $where .= ' AND (b.expires_at IS NULL OR b.expires_at > UTC_TIMESTAMP())';
}
if ($q !== '') {
    $where .= ' AND (b.fqdn LIKE ? OR b.reason LIKE ?)';
    $params[] = '%' . $q . '%';
    $params[] = '%' . $q . '%';
}

$cnt = db()->prepare('SELECT COUNT(*) c FROM fqdn_bans b' . $where);
$cnt->execute($params);
$pager = pager_window((int)$cnt->fetch()['c']);

$sql = 'SELECT b.id, b.fqdn, b.reason, b.expires_at, b.created_at,
               u.username AS created_by_name
        FROM fqdn_bans b
        LEFT JOIN users u ON u.id = b.created_by'
     . $where . ' ORDER BY b.created_at DESC LIMIT ? OFFSET ?';
$stmt = db()->prepare($sql);
$i = 1;
foreach ($params as $p) {
    $stmt->bindValue($i++, $p, PDO::PARAM_STR);
}
$stmt->bindValue($i++, $pager['limit'], PDO::PARAM_INT);
$stmt->bindValue($i,   $pager['offset'], PDO::PARAM_INT);
$stmt->execute();
$rows = $stmt->fetchAll();

$page_title = 'fqdn bans';
include __DIR__ . '/private/header.php';
?>
<section class="card" id="add">
  <h1>fqdn bans</h1>
  <?php if (role_can_write($u)): ?>
  <form method="post" class="add-form">
    <?= csrf_field() ?>
    <input type="hidden" name="action" value="add">
    <label>fqdn(s)
      <textarea name="fqdn" rows="3" required spellcheck="false"
                placeholder="badsite.example.com&#10;phish.invalid"></textarea>
    </label>
    <label>reason
      <input type="text" name="reason" maxlength="255" placeholder="optional">
    </label>
    <label>duration
      <input type="text" name="duration" maxlength="20"
             placeholder="blank = default" value="<?= e(dur_prefill()) ?>">
    </label>
    <button type="submit">add</button>
  </form>
  <p class="sub duration-help">
    duration shortcuts (click to fill):
    <a class="dur-pick" href="<?= e(dur_pick_link('30s')) ?>">30s</a> seconds &middot;
    <a class="dur-pick" href="<?= e(dur_pick_link('30m')) ?>">30m</a> minutes &middot;
    <a class="dur-pick" href="<?= e(dur_pick_link('2h')) ?>">2h</a> hours &middot;
    <a class="dur-pick" href="<?= e(dur_pick_link('7d')) ?>">7d</a> days &middot;
    <a class="dur-pick" href="<?= e(dur_pick_link('2w')) ?>">2w</a> weeks &middot;
    <a class="dur-pick" href="<?= e(dur_pick_link('1mo')) ?>">1mo</a> months &middot;
    <a class="dur-pick" href="<?= e(dur_pick_link('1y')) ?>">1y</a> years &middot;
    <a class="dur-pick" href="<?= e(dur_pick_link('p')) ?>">p</a> or
    <a class="dur-pick" href="<?= e(dur_pick_link('permanent')) ?>">permanent</a>.
    Blank = system default (permanent unless changed in settings).
  </p>
  <?php endif; ?>
</section>

<section class="card">
  <form method="get" class="filter">
    <input type="text" name="q" value="<?= e($q) ?>" placeholder="search fqdn or reason">
    <label><input type="checkbox" name="expired" value="1" <?= $show_expired ? 'checked' : '' ?>> show expired</label>
    <button type="submit">filter</button>
  </form>

  <table class="grid-table">
    <thead>
      <tr>
        <th>fqdn</th><th>reason</th><th>by</th><th>added (<?= e(tz_abbrev()) ?>)</th><th>remaining</th>
        <?php if (role_can_write($u)): ?><th></th><?php endif; ?>
      </tr>
    </thead>
    <tbody>
    <?php foreach ($rows as $r): ?>
      <tr>
        <td class="mono"><?= e($r['fqdn']) ?></td>
        <td><?= e($r['reason'] ?? '') ?></td>
        <td><?= e($r['created_by_name'] ?? '?') ?></td>
        <td class="mono dim"><?= e(format_local($r['created_at'])) ?></td>
        <td class="mono"><?= e(format_duration_remaining($r['expires_at'])) ?></td>
        <?php if (role_can_write($u)): ?>
        <td class="actions">
          <a class="btn-del" href="<?= e(confirm_link('delete', (int)$r['id'])) ?>">del</a>
          <form method="post" class="inline">
            <?= csrf_field() ?>
            <input type="hidden" name="action" value="extend">
            <input type="hidden" name="id" value="<?= (int)$r['id'] ?>">
            <input type="text" name="extend" size="6" placeholder="2h" maxlength="20">
            <button type="submit">set</button>
          </form>
        </td>
        <?php endif; ?>
      </tr>
    <?php endforeach; ?>
    <?php if (!$rows): ?>
      <tr><td colspan="6" class="dim">no entries</td></tr>
    <?php endif; ?>
    </tbody>
  </table>
  <?= pager_render($pager) ?>
</section>
<?php include __DIR__ . '/private/footer.php'; ?>
