-- v0.3 schema changes for php-banlist
-- Applied by install.php; do not run manually.
--
-- Adds persistent "remember me" login support. Tokens use the
-- selector/validator pattern: the selector is a public lookup handle and the
-- validator's SHA-256 is stored (never the validator itself). Rows are
-- removed automatically when the owning user is deleted (ON DELETE CASCADE)
-- and pruned at expiry by cron/expire.php.

SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE TABLE IF NOT EXISTS remember_tokens (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    selector CHAR(32) NOT NULL,
    validator_hash CHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME NULL,
    user_agent_hash CHAR(64) NULL,
    UNIQUE KEY uniq_selector (selector),
    KEY idx_user (user_id),
    KEY idx_expires (expires_at),
    CONSTRAINT fk_remember_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
