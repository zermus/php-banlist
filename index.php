<?php
declare(strict_types=1);
require_once __DIR__ . '/private/auth.php';
$u = require_login();

$pdo = db();

$ip_total   = (int)$pdo->query("SELECT COUNT(*) c FROM ip_bans WHERE expires_at IS NULL OR expires_at > UTC_TIMESTAMP()")->fetch()['c'];
$ip_perm    = (int)$pdo->query("SELECT COUNT(*) c FROM ip_bans WHERE expires_at IS NULL")->fetch()['c'];
$ip_temp    = $ip_total - $ip_perm;
$fqdn_total  = (int)$pdo->query("SELECT COUNT(*) c FROM fqdn_bans WHERE expires_at IS NULL OR expires_at > UTC_TIMESTAMP()")->fetch()['c'];
$fqdn_perm   = (int)$pdo->query("SELECT COUNT(*) c FROM fqdn_bans WHERE expires_at IS NULL")->fetch()['c'];
$fqdn_temp   = $fqdn_total - $fqdn_perm;

$default_to = (int)setting('default_timeout_seconds', '0');
// config loaded lazily
$base = base_path();

$page_title = 'dashboard';
include __DIR__ . '/private/header.php';
?>
<section class="grid">
  <div class="card">
    <h2>ip bans</h2>
    <div class="big"><?= $ip_total ?></div>
    <div class="sub">active &middot; <?= $ip_perm ?> permanent &middot; <?= $ip_temp ?> timed</div>
    <a class="btn" href="<?= e($base) ?>/ip-bans.php">manage</a>
  </div>
  <div class="card">
    <h2>fqdn bans</h2>
    <div class="big"><?= $fqdn_total ?></div>
    <div class="sub">active &middot; <?= $fqdn_perm ?> permanent &middot; <?= $fqdn_temp ?> timed</div>
    <a class="btn" href="<?= e($base) ?>/fqdn-bans.php">manage</a>
  </div>
  <div class="card">
    <h2>feed endpoints</h2>
    <pre class="endpoints">GET <a href="<?= e($base) ?>/IP-list.txt" target="_blank" rel="noopener noreferrer"><?= e($base) ?>/IP-list.txt</a>
GET <a href="<?= e($base) ?>/FQDN-list.txt" target="_blank" rel="noopener noreferrer"><?= e($base) ?>/FQDN-list.txt</a></pre>
    <div class="sub">default timeout: <?= $default_to === 0 ? 'permanent' : human_seconds($default_to) ?></div>
  </div>
</section>

<?php
function human_seconds(int $s): string {
    if ($s < 60)    return $s . 's';
    if ($s < 3600)  return intdiv($s, 60) . 'm';
    if ($s < 86400) return intdiv($s, 3600) . 'h';
    return intdiv($s, 86400) . 'd';
}
include __DIR__ . '/private/footer.php';
?>
