<?php
/**
 * PDO database connection.
 * Returns a singleton PDO instance configured for prepared statements only.
 */
declare(strict_types=1);

/**
 * Application version. Bumped on each release. Pre-1.0 = testing/unstable;
 * minor bumps may include schema migrations and breaking changes.
 */
const PBL_VERSION = '0.5';

if (!defined('PHPBANLIST_VERSION')) {
    define('PHPBANLIST_VERSION', '0.5');
}

/**
 * Load app config from the project root.
 * config.php lives one directory above this file (root of the install).
 */
function load_config(): array {
    static $cfg = null;
    if ($cfg !== null) {
        return $cfg;
    }
    $path = __DIR__ . '/../config.php';
    if (!is_file($path)) {
        http_response_code(500);
        exit("php-banlist: config.php not found at " . htmlspecialchars($path)
           . ". Copy config.example.php to config.php and edit it.\n");
    }
    $cfg = require $path;
    if (!is_array($cfg)) {
        http_response_code(500);
        exit("php-banlist: config.php did not return an array.\n");
    }
    return $cfg;
}

function db(): PDO {
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }

    $cfg = load_config();
    $d   = $cfg['db'];

    // Prefer Unix socket if configured (faster, no TCP overhead on a LAMP box)
    if (!empty($d['socket'])) {
        $dsn = sprintf(
            'mysql:unix_socket=%s;dbname=%s;charset=%s',
            $d['socket'], $d['name'], $d['charset']
        );
    } else {
        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=%s',
            $d['host'], $d['port'], $d['name'], $d['charset']
        );
    }

    $opts = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        // Real prepared statements at the protocol level. No emulation.
        PDO::ATTR_EMULATE_PREPARES   => false,
        PDO::ATTR_STRINGIFY_FETCHES  => false,
        PDO::MYSQL_ATTR_FOUND_ROWS   => true,
    ];

    $pdo = new PDO($dsn, $d['user'], $d['pass'], $opts);
    $pdo->exec("SET time_zone = '+00:00'");
    return $pdo;
}

/**
 * Read a setting from the settings table with a fallback.
 */
function setting(string $key, $default = null): ?string {
    $stmt = db()->prepare('SELECT value FROM settings WHERE key_name = ?');
    $stmt->execute([$key]);
    $row = $stmt->fetch();
    return $row ? $row['value'] : $default;
}

function setting_set(string $key, ?string $value): void {
    $stmt = db()->prepare(
        'INSERT INTO settings (key_name, value) VALUES (?, ?)
         ON DUPLICATE KEY UPDATE value = VALUES(value)'
    );
    $stmt->execute([$key, $value]);
}

/* -------------------- Migrations -------------------- */

/**
 * Split a multi-statement SQL string into individual statements.
 * Handles -- and /* *\/ comments, single and double quoted strings.
 * Good enough for the controlled DDL we ship in sql/migrations/.
 */
function split_sql_statements(string $sql): array {
    // Strip block comments
    $sql = preg_replace('/\/\*.*?\*\//s', '', $sql) ?? $sql;
    // Strip line comments
    $sql = preg_replace('/^\s*--[^\n]*$/m', '', $sql) ?? $sql;

    $stmts   = [];
    $current = '';
    $in_s    = false;
    $in_d    = false;
    $len     = strlen($sql);
    for ($i = 0; $i < $len; $i++) {
        $c = $sql[$i];
        if (!$in_s && !$in_d && $c === ';') {
            $t = trim($current);
            if ($t !== '') $stmts[] = $t;
            $current = '';
            continue;
        }
        if ($c === "'" && !$in_d) {
            if ($in_s && $i + 1 < $len && $sql[$i + 1] === "'") {
                $current .= "''";
                $i++;
                continue;
            }
            $in_s = !$in_s;
        } elseif ($c === '"' && !$in_s) {
            $in_d = !$in_d;
        }
        $current .= $c;
    }
    $t = trim($current);
    if ($t !== '') $stmts[] = $t;
    return $stmts;
}

/**
 * Ensure the schema_migrations table exists. Safe to call before any migration.
 */
function ensure_migrations_table(PDO $pdo): void {
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version    VARCHAR(64) NOT NULL PRIMARY KEY,
            applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");
}

/**
 * Apply any pending migrations from sql/migrations/.
 *
 * Returns ['applied' => string[], 'baselined' => bool] where:
 *  - applied: list of versions actually executed in this call
 *  - baselined: true if we marked an existing DB as already at v0001 without
 *               running it (i.e. the user had imported the old schema.sql by
 *               hand on a previous version of the app)
 */
function run_pending_migrations(string $migrations_dir): array {
    $pdo = db();
    ensure_migrations_table($pdo);

    // Already-applied set
    $stmt = $pdo->query("SELECT version FROM schema_migrations");
    $applied = [];
    foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $v) {
        $applied[$v] = true;
    }

    // Available migration files, sorted by name (numeric prefix sorts naturally)
    $files = glob($migrations_dir . '/*.sql') ?: [];
    sort($files);

    $newly = [];
    $baselined = false;

    // Baseline check: if users table already exists but no migrations recorded,
    // assume the DB was imported by hand at v0001 and mark it applied.
    if (empty($applied)) {
        $has_users = false;
        try {
            $pdo->query("SELECT 1 FROM users LIMIT 0");
            $has_users = true;
        } catch (PDOException $e) {
            // table doesn't exist; this is a fresh install
        }
        if ($has_users && $files) {
            $first = basename($files[0], '.sql');
            $pdo->prepare("INSERT INTO schema_migrations (version) VALUES (?)")
                ->execute([$first]);
            $applied[$first] = true;
            $baselined = true;
        }
    }

    foreach ($files as $file) {
        $version = basename($file, '.sql');
        if (isset($applied[$version])) continue;

        $sql = file_get_contents($file);
        if ($sql === false) {
            throw new RuntimeException("Cannot read migration file: $file");
        }

        // DDL implicitly commits in MySQL, so a transaction here is mostly
        // for the INSERT into schema_migrations. We still wrap for clarity.
        foreach (split_sql_statements($sql) as $stmt) {
            $pdo->exec($stmt);
        }
        $pdo->prepare("INSERT INTO schema_migrations (version) VALUES (?)")
            ->execute([$version]);
        $newly[] = $version;
    }

    return ['applied' => $newly, 'baselined' => $baselined];
}
