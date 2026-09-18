<?php
declare(strict_types=1);
require_once __DIR__ . '/private/auth.php';
$u = require_login();

// config loaded lazily
$base = base_path();

// POST actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    if (!role_can_write($u)) {
        flash('error', 'Read-only account cannot modify the list.');
        header('Location: ' . $base . '/ip-bans.php' . list_state_qs());
        exit;
    }
    $action = (string)($_POST['action'] ?? '');
    if ($action === 'add' || $action === 'confirm_broad_add') {
        $confirmed = $action === 'confirm_broad_add';
        if ($confirmed) {
            $payload = broad_add_confirmation_consume((string)($_POST['confirmation_token'] ?? ''));
            if ($payload === null) {
                flash('error', 'Broad-subnet confirmation expired, was already used, or is invalid. Nothing was added.');
                header('Location: ' . $base . '/ip-bans.php' . list_state_qs());
                exit;
            }
            $raw = (string)($payload['ip'] ?? '');
            $reason = trim((string)($payload['reason'] ?? ''));
            $dur_in = (string)($payload['duration'] ?? '');
            $confirmed_warnings = is_array($payload['warnings'] ?? null) ? $payload['warnings'] : [];
        } else {
            $raw = (string)($_POST['ip'] ?? '');
            $reason = trim((string)($_POST['reason'] ?? ''));
            $dur_in = (string)($_POST['duration'] ?? '');
            $confirmed_warnings = [];
        }

        $guardrails = cidr_guardrails();
        $lines = preg_split('/[\r\n,]+/', $raw) ?: [];
        $preflight = ip_ban_preflight($lines, $guardrails);
        if ($preflight['invalid'] || $preflight['rejected']) {
            $parts = [];
            if ($preflight['invalid']) {
                $parts[] = count($preflight['invalid']) . ' invalid';
            }
            if ($preflight['rejected']) {
                $parts[] = count($preflight['rejected']) . ' at or broader than the hard cutoff: '
                    . implode(' ', array_slice($preflight['rejected'], 0, 5));
            }
            flash('error', 'Nothing added; ' . implode(', ', $parts) . '.');
            header('Location: ' . $base . '/ip-bans.php' . list_state_qs());
            exit;
        }
        if (!$preflight['entries']) {
            flash('error', 'Nothing added; enter at least one valid IP address or CIDR.');
            header('Location: ' . $base . '/ip-bans.php' . list_state_qs());
            exit;
        }
        if ($confirmed && !broad_add_confirmation_is_current($payload, $preflight, $guardrails)) {
            flash('error', 'Subnet guard rails changed; review and confirm the request again. Nothing was added.');
            header('Location: ' . $base . '/ip-bans.php' . list_state_qs());
            exit;
        }

        if ($preflight['warnings'] && !$confirmed) {
            $token = broad_add_confirmation_issue([
                'ip' => $raw,
                'reason' => $reason,
                'duration' => $dur_in,
                'warnings' => $preflight['warnings'],
                'guardrails' => $guardrails,
            ]);
            $page_title = 'confirm broad subnets';
            include __DIR__ . '/private/header.php';
            ?>
            <section class="card confirm-card">
              <h1>confirm broad subnet ban</h1>
              <p class="confirm-prompt">The following CIDRs are at or broader than the warning cutoff:</p>
              <pre class="confirm-targets"><?= e(implode("\n", $preflight['warnings'])) ?></pre>
              <p class="confirm-prompt">This can block large address ranges. Confirm this exact one-time request?</p>
              <div class="confirm-actions">
                <form method="post" class="inline">
                  <?= csrf_field() ?>
                  <input type="hidden" name="action" value="confirm_broad_add">
                  <input type="hidden" name="confirmation_token" value="<?= e($token) ?>">
                  <button type="submit" class="danger">add broad subnet(s)</button>
                </form>
                <a class="btn-cancel" href="<?= e($base) ?>/ip-bans.php<?= e(list_state_qs()) ?>">cancel</a>
              </div>
            </section>
            <?php
            include __DIR__ . '/private/footer.php';
            exit;
        }

        $default_to = (int)setting('default_timeout_seconds', '0');
        if ($dur_in === '') {
            $duration = $default_to === 0
                ? ['expires_at' => null, 'permanent' => true]
                : ['expires_at' => gmdate('Y-m-d H:i:s', time() + $default_to), 'permanent' => false];
        } else {
            $duration = parse_duration($dur_in);
            if ($duration === null) {
                flash('error', 'Bad duration. Use 30m, 2h, 7d, 1mo, 1y, or p.');
                header('Location: ' . $base . '/ip-bans.php' . list_state_qs());
                exit;
            }
        }

        $exp = $duration['permanent'] ? null : $duration['expires_at'];
        $pdo = db();
        $stmt = $pdo->prepare(
            'INSERT INTO ip_bans (ip_address, reason, created_by, expires_at)
             VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE reason = VALUES(reason),
                                     created_by = VALUES(created_by),
                                     expires_at = VALUES(expires_at)'
        );
        $pdo->beginTransaction();
        try {
            foreach ($preflight['entries'] as $entry) {
                $norm = $entry['normalized'];
                $stmt->execute([$norm, $reason !== '' ? $reason : null, (int)$u['id'], $exp]);
                audit_log_write((int)$u['id'], $u['username'], 'ip_ban_add', $norm,
                                $exp ? "expires={$exp}" : 'permanent');
                if ($confirmed && in_array($norm, $confirmed_warnings, true)) {
                    audit_log_write((int)$u['id'], $u['username'], 'broad_ip_ban_confirm', $norm,
                                    "{$entry['family']} prefix=/{$entry['prefix']}");
                }
            }
            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            throw $e;
        }
        flash('ok', 'added ' . count($preflight['entries']));

    } elseif ($action === 'delete') {
        $id = (int)($_POST['id'] ?? 0);
        $row = db()->prepare('SELECT ip_address FROM ip_bans WHERE id = ?');
        $row->execute([$id]);
        $found = $row->fetch();
        if ($found) {
            db()->prepare('DELETE FROM ip_bans WHERE id = ?')->execute([$id]);
            audit_log_write((int)$u['id'], $u['username'], 'ip_ban_del', $found['ip_address'], null);
            flash('ok', 'Removed ' . $found['ip_address']);
        }
    } elseif ($action === 'extend') {
        $id  = (int)($_POST['id'] ?? 0);
        $dur = parse_duration((string)($_POST['extend'] ?? ''));
        if ($dur === null) {
            flash('error', 'Bad duration.');
        } else {
            if ($dur['permanent']) {
                db()->prepare('UPDATE ip_bans SET expires_at = NULL WHERE id = ?')->execute([$id]);
                flash('ok', 'Set permanent.');
            } else {
                $exp = $dur['expires_at'];
                db()->prepare('UPDATE ip_bans SET expires_at = ? WHERE id = ?')->execute([$exp, $id]);
                flash('ok', 'New expiry ' . format_local($exp) . ' ' . tz_abbrev());
            }
            audit_log_write((int)$u['id'], $u['username'], 'ip_ban_extend', (string)$id, null);
        }
    }
    header('Location: ' . $base . '/ip-bans.php' . list_state_qs());
    exit;
}

// JS-free delete confirmation interstitial (replaces the dead inline
// onsubmit="confirm()" handler, which never fired under the strict CSP).
if (role_can_write($u) && ($cr = confirm_request(['delete']))) {
    $row = db()->prepare('SELECT ip_address FROM ip_bans WHERE id = ?');
    $row->execute([$cr['id']]);
    $found = $row->fetch();
    if ($found) {
        $page_title = 'confirm';
        include __DIR__ . '/private/header.php';
        echo confirm_card(
            $base . '/ip-bans.php',
            'Remove ban on <strong class="mono">' . e($found['ip_address']) . '</strong>?',
            'delete',
            $cr['id'],
            'del'
        );
        include __DIR__ . '/private/footer.php';
        exit;
    }
}

// Listing with optional search
$q = trim((string)($_GET['q'] ?? ''));
$show_expired = !empty($_GET['expired']);

$where = ' WHERE 1=1';
$params = [];
if (!$show_expired) {
    $where .= ' AND (b.expires_at IS NULL OR b.expires_at > UTC_TIMESTAMP())';
}
if ($q !== '') {
    $where .= ' AND (b.ip_address LIKE ? OR b.reason LIKE ?)';
    $params[] = '%' . $q . '%';
    $params[] = '%' . $q . '%';
}

$cnt = db()->prepare('SELECT COUNT(*) c FROM ip_bans b' . $where);
$cnt->execute($params);
$pager = pager_window((int)$cnt->fetch()['c']);

$sql = 'SELECT b.id, b.ip_address, b.reason, b.expires_at, b.created_at,
               u.username AS created_by_name
        FROM ip_bans b
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

$page_title = 'ip bans';
include __DIR__ . '/private/header.php';
?>
<section class="card" id="add">
  <h1>ip bans</h1>
  <?php if (role_can_write($u)): ?>
  <form method="post" class="add-form">
    <?= csrf_field() ?>
    <input type="hidden" name="action" value="add">
    <label>address(es) / CIDR
      <textarea name="ip" rows="3" required spellcheck="false"
                placeholder="203.0.113.5&#10;2001:db8::/32"></textarea>
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
    <input type="text" name="q" value="<?= e($q) ?>" placeholder="search ip or reason">
    <label><input type="checkbox" name="expired" value="1" <?= $show_expired ? 'checked' : '' ?>> show expired</label>
    <button type="submit">filter</button>
  </form>

  <table class="grid-table">
    <thead>
      <tr>
        <th>ip / cidr</th><th>reason</th><th>by</th><th>added (<?= e(tz_abbrev()) ?>)</th><th>remaining</th>
        <?php if (role_can_write($u)): ?><th></th><?php endif; ?>
      </tr>
    </thead>
    <tbody>
    <?php foreach ($rows as $r): ?>
      <tr>
        <td class="mono"><?= e($r['ip_address']) ?></td>
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
