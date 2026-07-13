<?php
declare(strict_types=1);
require_once __DIR__ . '/private/auth.php';
$u = require_login();

// config loaded lazily
$base = base_path();

$q = trim((string)($_GET['q'] ?? ''));
$where = '';
$params = [];
if ($q !== '') {
    $where = ' WHERE username LIKE ? OR action LIKE ? OR target LIKE ? OR ip_address LIKE ?';
    $params = ['%'.$q.'%','%'.$q.'%','%'.$q.'%','%'.$q.'%'];
}

$cnt = db()->prepare('SELECT COUNT(*) c FROM audit_log' . $where);
$cnt->execute($params);
$pager = pager_window((int)$cnt->fetch()['c']);

$sql = 'SELECT created_at, username, action, target, details, ip_address FROM audit_log'
     . $where . ' ORDER BY id DESC LIMIT ? OFFSET ?';
$stmt = db()->prepare($sql);
$i = 1;
foreach ($params as $p) {
    $stmt->bindValue($i++, $p, PDO::PARAM_STR);
}
$stmt->bindValue($i++, $pager['limit'], PDO::PARAM_INT);
$stmt->bindValue($i,   $pager['offset'], PDO::PARAM_INT);
$stmt->execute();
$rows = $stmt->fetchAll();

$page_title = 'audit log';
include __DIR__ . '/private/header.php';
?>
<section class="card">
  <h1>audit log</h1>
  <form method="get" class="filter">
    <input type="text" name="q" value="<?= e($q) ?>" placeholder="user, action, target, ip">
    <button type="submit">filter</button>
  </form>
  <table class="grid-table">
    <thead><tr><th>when (<?= e(tz_abbrev()) ?>)</th><th>user</th><th>action</th><th>target</th><th>details</th><th>ip</th></tr></thead>
    <tbody>
    <?php foreach ($rows as $r): ?>
      <tr>
        <td class="mono dim"><?= e(format_local($r['created_at'], 'Y-m-d H:i:s')) ?></td>
        <td><?= e($r['username'] ?? '?') ?></td>
        <td class="mono"><?= e($r['action']) ?></td>
        <td class="mono"><?= e($r['target'] ?? '') ?></td>
        <td class="dim"><?= e($r['details'] ?? '') ?></td>
        <td class="mono dim"><?= e($r['ip_address'] ?? '') ?></td>
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
