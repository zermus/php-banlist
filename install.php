<?php
/**
 * Install / upgrade script.
 *
 *  - On a fresh DB: applies every migration in sql/migrations/, then asks
 *    you to create the initial superadmin.
 *  - On an existing DB with pending migrations: applies the new migrations
 *    and shows what was done.
 *  - On a DB that was set up by hand from an old schema.sql before this
 *    migration system existed: marks 0001-initial as already applied
 *    (baseline) and continues with any later migrations.
 *  - Once everything is up to date and a user exists: refuses to run and
 *    asks you to delete the file.
 *
 * Re-upload this file when upgrading. Delete it again when done.
 */
declare(strict_types=1);
require_once __DIR__ . '/private/db.php';
require_once __DIR__ . '/private/functions.php';
require_once __DIR__ . '/private/auth.php';

$cfg           = load_config();
$min_length    = (int)($cfg['passwords']['min_length'] ?? 14);
$require_mixed = !empty($cfg['passwords']['require_mixed']);

$err_msg   = null;   // shown as red
$ok_msg    = null;   // shown as green
$show_form = false;
$migration_info = null;

/* -------------------- Step 1: connect + migrate -------------------- */

try {
    $pdo = db();
} catch (Throwable $e) {
    http_response_code(500);
    $err_msg = "Could not connect to the database. Verify config.php has the correct "
             . "credentials and the database exists. PDO error: " . $e->getMessage();
}

if (!$err_msg) {
    try {
        $migration_info = run_pending_migrations(__DIR__ . '/sql/migrations');
    } catch (PDOException $e) {
        $code = $e->errorInfo[1] ?? null;
        // 1142 = ER_TABLEACCESS_DENIED_ERROR (CREATE/INSERT/etc on a table)
        // 1227 = ER_SPECIFIC_ACCESS_DENIED_ERROR (global privs missing)
        // 1044 = ER_DBACCESS_DENIED_ERROR (no access to the DB at all)
        if (in_array($code, [1142, 1227, 1044], true)) {
            // Try to extract the DB and user from the configured creds so the
            // GRANT line we suggest is copy-paste accurate.
            $d = $cfg['db'];
            $dbname = preg_replace('/[^A-Za-z0-9_]/', '', (string)$d['name']);
            $dbuser = preg_replace('/[^A-Za-z0-9_]/', '', (string)$d['user']);
            $grant_sql  = "GRANT CREATE, ALTER, INDEX, DROP, REFERENCES "
                        . "ON `{$dbname}`.* TO '{$dbuser}'@'localhost'; FLUSH PRIVILEGES;";
            $revoke_sql = "REVOKE CREATE, ALTER, INDEX, DROP "
                        . "ON `{$dbname}`.* FROM '{$dbuser}'@'localhost';";
            $err_msg = "The MySQL user used by php-banlist does not have permission "
                     . "to apply schema changes. To run migrations, grant the DDL "
                     . "privileges below, refresh this page, then optionally revoke "
                     . "them again afterward.\n\n"
                     . "Grant (run as root or another privileged account):\n"
                     . "  {$grant_sql}\n\n"
                     . "Revoke (after install completes):\n"
                     . "  {$revoke_sql}\n\n"
                     . "Original error: " . $e->getMessage();
        } else {
            $err_msg = "Migration failed: " . $e->getMessage();
        }
    } catch (Throwable $e) {
        http_response_code(500);
        $err_msg = "Migration failed: " . $e->getMessage();
    }
}

/* -------------------- Step 2: decide what to show -------------------- */

$user_count = 0;
if (!$err_msg) {
    try {
        $user_count = (int)$pdo->query('SELECT COUNT(*) c FROM users')->fetch()['c'];
    } catch (Throwable $e) {
        $err_msg = "Could not count users: " . $e->getMessage();
    }
}

if (!$err_msg) {
    // Build a status banner from what just happened
    $status_parts = [];
    if ($migration_info['applied']) {
        $status_parts[] = "Applied migrations: " . implode(', ', $migration_info['applied']) . ".";
    }
    if ($migration_info['baselined']) {
        $status_parts[] = "Detected existing database; marked initial schema as baseline.";
    }
    if ($status_parts) {
        $ok_msg = implode(' ', $status_parts);
    }

    // Decide whether to show the create-superadmin form, the "already
    // installed" lock page, or both messages.
    if ($user_count === 0) {
        // Fresh DB (or never created the first admin): show the form.
        $show_form = true;
    } elseif (!$migration_info['applied'] && !$migration_info['baselined']) {
        // Already installed and nothing changed: auto-lock.
        http_response_code(403);
        ?>
<!doctype html><meta charset=utf-8>
<title>install :: php-banlist</title>
<style>
body{font-family:"Fira Code",monospace;background:#0a0e0a;color:#cfe5d2;max-width:560px;margin:60px auto;padding:24px;border:1px solid #1f3a23;border-radius:4px;line-height:1.5}
h1{color:#39ff14;margin:0 0 14px;font-size:18px}
.msg{padding:10px 14px;background:#0e140e;border:1px solid #1f3a23;border-radius:3px;margin:8px 0;font-size:13px;color:#39ff14}
</style>
<h1>php-banlist install <span style="color:#7aa07f;font-size:12px;">v<?= e(PHPBANLIST_VERSION) ?></span></h1>
<div class="msg">Already installed and up to date. Delete install.php from disk.</div>
        <?php
        exit;
    }
    // Otherwise (user exists AND migrations were just applied): fall through
    // with $ok_msg set, $show_form stays false. The page will render the
    // status and the "delete this file" note.
}

/* -------------------- Step 3: handle the create-superadmin POST -------- */

if (!$err_msg && $_SERVER['REQUEST_METHOD'] === 'POST' && $user_count === 0) {
    $username  = trim((string)($_POST['username'] ?? ''));
    $password  = (string)($_POST['password'] ?? '');
    $password2 = (string)($_POST['password_confirm'] ?? '');

    if (!preg_match('/^[A-Za-z0-9_.\-]{2,64}$/', $username)) {
        $err_msg = 'Username: 2-64 chars [A-Za-z0-9_.-]';
    } elseif ($password !== $password2) {
        $err_msg = 'Passwords do not match.';
    } elseif (($policy_err = validate_password_policy($password)) !== null) {
        $err_msg = $policy_err;
    } else {
        $hash = password_hash($password, password_algo_default());
        $pdo->prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
            ->execute([$username, $hash, 'superadmin']);
        $ok_msg = "OK. Created superadmin '{$username}'. Delete install.php now.";
        $show_form = false;
    }
}

?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>install :: php-banlist</title>
<style>
:root {
  --bg:#0a0e0a;--bg-2:#0e140e;--fg:#cfe5d2;--fg-dim:#7aa07f;
  --accent:#39ff14;--warn:#ffb13b;--error:#ff5c4e;--border:#1f3a23;
}
*{box-sizing:border-box;}
body{font-family:"Fira Code",ui-monospace,Menlo,Consolas,monospace;background:var(--bg);color:var(--fg);
     max-width:560px;margin:60px auto;padding:24px;border:1px solid var(--border);border-radius:4px;line-height:1.5;}
h1{color:var(--accent);margin:0 0 16px;font-size:18px;letter-spacing:.5px;}
label{display:block;margin:14px 0 4px;font-size:12px;color:var(--fg-dim);}
input,button{display:block;width:100%;margin:0;padding:8px 10px;background:var(--bg);color:var(--fg);
             border:1px solid var(--border);border-radius:3px;font:inherit;outline:none;}
input:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(57,255,20,.15);}
button{margin-top:18px;background:transparent;color:var(--accent);border-color:#2a5a32;cursor:pointer;
       padding:10px;font-size:14px;}
button:hover:not(:disabled){background:rgba(57,255,20,.08);}
button:disabled{opacity:.4;cursor:not-allowed;}
.msg{padding:10px 14px;background:var(--bg-2);border:1px solid var(--border);border-radius:3px;
     margin:0 0 12px;font-size:13px;}
.msg.ok{color:var(--accent);border-color:rgba(57,255,20,.3);}
.msg.error{color:var(--error);border-color:rgba(255,92,78,.3);}
.checklist{list-style:none;padding:10px 14px;margin:8px 0 0;background:var(--bg-2);
           border:1px solid var(--border);border-radius:3px;font-size:12px;}
.checklist li{display:flex;align-items:center;gap:8px;padding:2px 0;color:var(--fg-dim);transition:color .1s;}
.checklist li::before{content:"[ ]";color:var(--fg-dim);width:24px;display:inline-block;}
.checklist li.ok{color:var(--accent);}
.checklist li.ok::before{content:"[x]";color:var(--accent);}
.checklist li.fail{color:var(--error);}
.checklist li.fail::before{content:"[!]";color:var(--error);}
.note{opacity:.7;font-size:11px;margin-top:20px;}
</style>
</head>
<body>
<h1>php-banlist install <span style="color:var(--fg-dim);font-size:12px;">v<?= e(PHPBANLIST_VERSION) ?></span></h1>

<?php if ($err_msg): ?>
  <div class="msg error"><?= e($err_msg) ?></div>
<?php endif; ?>

<?php if ($ok_msg): ?>
  <div class="msg ok"><?= e($ok_msg) ?></div>
<?php endif; ?>

<?php if ($show_form): ?>
<form method="post" autocomplete="off" novalidate id="install-form">
  <label for="username">superadmin username</label>
  <input type="text" id="username" name="username" required
         pattern="[A-Za-z0-9_.\-]{2,64}" maxlength="64"
         autocapitalize="off" autocorrect="off" spellcheck="false">

  <label for="pw">password</label>
  <input type="password" id="pw" name="password" required
         minlength="<?= (int)$min_length ?>" maxlength="256">

  <label for="pw2">confirm password</label>
  <input type="password" id="pw2" name="password_confirm" required
         minlength="<?= (int)$min_length ?>" maxlength="256">

  <ul class="checklist" id="checks" aria-live="polite">
    <li id="c-length"  data-test="length"><?= (int)$min_length ?>+ characters</li>
<?php if ($require_mixed): ?>
    <li id="c-lower"   data-test="lower">lowercase letter (a-z)</li>
    <li id="c-upper"   data-test="upper">uppercase letter (A-Z)</li>
    <li id="c-digit"   data-test="digit">digit (0-9)</li>
    <li id="c-symbol"  data-test="symbol">symbol (!@#$ etc.)</li>
<?php endif; ?>
    <li id="c-match"   data-test="match">passwords match</li>
  </ul>

  <button type="submit" id="submit-btn" disabled>create superadmin</button>
</form>

<script>
(function () {
  var minLen     = <?= (int)$min_length ?>;
  var checkMixed = <?= $require_mixed ? 'true' : 'false' ?>;
  var pw   = document.getElementById('pw');
  var pw2  = document.getElementById('pw2');
  var btn  = document.getElementById('submit-btn');
  var user = document.getElementById('username');

  function setState(li, state) {
    if (!li) return;
    li.classList.remove('ok', 'fail');
    if (state === 'ok')   li.classList.add('ok');
    if (state === 'fail') li.classList.add('fail');
  }

  function run() {
    var p = pw.value;
    var p2 = pw2.value;
    var checks = {
      length: p.length >= minLen,
      lower:  /[a-z]/.test(p),
      upper:  /[A-Z]/.test(p),
      digit:  /\d/.test(p),
      symbol: /[^A-Za-z0-9]/.test(p),
      match:  p.length > 0 && p === p2
    };
    document.querySelectorAll('.checklist li').forEach(function (li) {
      var key = li.getAttribute('data-test');
      if (p.length === 0 && key !== 'match') { setState(li, null); return; }
      if (key === 'match' && p2.length === 0) { setState(li, null); return; }
      setState(li, checks[key] ? 'ok' : 'fail');
    });
    var pwOk = checks.length && checks.match
      && (!checkMixed || (checks.lower && checks.upper && checks.digit && checks.symbol));
    var userOk = /^[A-Za-z0-9_.\-]{2,64}$/.test(user.value);
    btn.disabled = !(pwOk && userOk);
  }

  pw.addEventListener('input', run);
  pw2.addEventListener('input', run);
  user.addEventListener('input', run);
  run();
})();
</script>
<?php endif; ?>

<p class="note">After success, delete this file from disk.</p>
</body>
</html>
