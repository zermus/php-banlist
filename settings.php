<?php
declare(strict_types=1);
require_once __DIR__ . '/private/auth.php';
$u = require_role('superadmin');

$base = base_path();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $dur = trim((string)($_POST['default_timeout'] ?? ''));
    if ($dur === '' || $dur === 'permanent' || $dur === '0' || $dur === 'p') {
        setting_set('default_timeout_seconds', '0');
    } else {
        $parsed = parse_duration($dur);
        if ($parsed === null) {
            flash('error', 'Bad duration. Use 30m, 2h, 7d, 1mo, 1y, or p.');
            header('Location: ' . $base . '/settings.php');
            exit;
        }
        setting_set('default_timeout_seconds', (string)($parsed['permanent'] ? 0 : (int)$parsed['seconds']));
    }

    $maxf = max(1, min(20, (int)($_POST['max_failed_logins'] ?? 5)));
    $lock = max(1, min(1440, (int)($_POST['lockout_minutes'] ?? 15)));
    $idle = max(0, min(1440, (int)($_POST['session_timeout_minutes'] ?? 30)));
    setting_set('max_failed_logins', (string)$maxf);
    setting_set('lockout_minutes', (string)$lock);
    setting_set('session_timeout_minutes', (string)$idle);

    $req_tok = !empty($_POST['require_token_for_lists']) ? '1' : '0';
    setting_set('require_token_for_lists', $req_tok);

    $write_api = !empty($_POST['enable_write_api']) ? '1' : '0';
    if ($write_api !== (string)setting('enable_write_api', '0')) {
        audit_log_write((int)$u['id'], $u['username'], 'write_api_toggle', null, "enabled={$write_api}");
    }
    setting_set('enable_write_api', $write_api);

    $tz = trim((string)($_POST['default_timezone'] ?? ''));
    if ($tz === '' || tz_is_valid($tz)) {
        setting_set('default_timezone', $tz);
    } else {
        flash('warn', 'Unknown timezone "' . e($tz) . '" was not saved.');
    }

    audit_log_write((int)$u['id'], $u['username'], 'settings_update', null, null);
    flash('ok', 'Settings saved.');
    header('Location: ' . $base . '/settings.php');
    exit;
}

$cur_to    = (int)setting('default_timeout_seconds', '0');
$cur_maxf  = (int)setting('max_failed_logins', '5');
$cur_lock  = (int)setting('lockout_minutes', '15');
$cur_idle  = (int)setting('session_timeout_minutes', '30');
$cur_req   = (int)setting('require_token_for_lists', '0');
$cur_api   = (int)setting('enable_write_api', '0');
$cur_tz    = (string)setting('default_timezone', '');

function display_duration(int $s): string {
    if ($s === 0)   return 'permanent';
    if ($s % 86400 === 0) return ($s / 86400) . 'd';
    if ($s % 3600 === 0)  return ($s / 3600) . 'h';
    if ($s % 60 === 0)    return ($s / 60) . 'm';
    return $s . 's';
}

$page_title = 'settings';
include __DIR__ . '/private/header.php';
?>
<section class="card">
  <h1>settings</h1>
  <form method="post" class="settings-form">
    <?= csrf_field() ?>

    <fieldset class="settings-group">
      <legend>ban defaults</legend>
      <div class="field">
        <label for="default_timeout">default timeout</label>
        <input type="text" id="default_timeout" name="default_timeout"
               value="<?= e(display_duration($cur_to)) ?>"
               placeholder="30m, 2h, 7d, 1mo, 1y, p">
        <small>used when the duration field is left blank on add</small>
      </div>
      <div class="field">
        <label for="default_timezone">default timezone for new users</label>
        <select id="default_timezone" name="default_timezone">
          <option value="">(server default: <?= e(date_default_timezone_get()) ?>)</option>
          <?php foreach (tz_groups() as $region => $list): ?>
            <optgroup label="<?= e($region) ?>">
              <?php foreach ($list as $tzid => $disp): ?>
                <option value="<?= e($tzid) ?>" <?= $cur_tz === $tzid ? 'selected' : '' ?>>
                  <?= e($tzid) ?> &mdash; <?= e($disp) ?>
                </option>
              <?php endforeach; ?>
            </optgroup>
          <?php endforeach; ?>
        </select>
        <small>applies when a user has not set their own timezone in their profile</small>
      </div>
    </fieldset>

    <fieldset class="settings-group">
      <legend>login &amp; session security</legend>
      <div class="field-row">
        <div class="field">
          <label for="max_failed_logins">max failed logins before lockout</label>
          <input type="number" id="max_failed_logins" name="max_failed_logins"
                 min="1" max="20" value="<?= (int)$cur_maxf ?>">
          <small>per account (1&ndash;20)</small>
        </div>
        <div class="field">
          <label for="lockout_minutes">lockout minutes</label>
          <input type="number" id="lockout_minutes" name="lockout_minutes"
                 min="1" max="1440" value="<?= (int)$cur_lock ?>">
          <small>how long a locked account stays locked (1&ndash;1440)</small>
        </div>
        <div class="field">
          <label for="session_timeout_minutes">idle timeout minutes</label>
          <input type="number" id="session_timeout_minutes" name="session_timeout_minutes"
                 min="0" max="1440" value="<?= (int)$cur_idle ?>">
          <small>sign out after inactivity; 0 disables (0&ndash;1440)</small>
        </div>
      </div>
      <p class="settings-note">
        per-IP brute-force limits are an operator hard floor set in
        <code>config.php</code> and are not editable here.
      </p>
    </fieldset>

    <fieldset class="settings-group">
      <legend>feeds &amp; api</legend>
      <div class="field">
        <label class="checkbox">
          <input type="checkbox" name="require_token_for_lists" value="1" <?= $cur_req ? 'checked' : '' ?>>
          require <code>?token=...</code> for /IP-list.txt and /FQDN-list.txt
        </label>
        <small>issue tokens on the tokens page; affects both feeds</small>
      </div>
      <div class="field">
        <label class="checkbox">
          <input type="checkbox" name="enable_write_api" value="1" <?= $cur_api ? 'checked' : '' ?>>
          enable the write API (<code>api.php</code>)
        </label>
        <small>tokens can add/remove bans only when this is on AND the token has its
               per-token write flag; existing tokens stay read-only either way</small>
      </div>
    </fieldset>

    <div class="settings-actions">
      <button type="submit">save</button>
    </div>
  </form>
</section>
<?php include __DIR__ . '/private/footer.php'; ?>
