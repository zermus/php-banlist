-- v0.4 schema changes for php-banlist
-- Applied by install.php; do not run manually.
--
-- Adds the write API:
--   * api_tokens.can_write: per-token opt-in allowing the token to add and
--     remove bans via api.php. Existing tokens stay read-only (feeds only).
--   * settings.enable_write_api: global off switch, default disabled. Both
--     the global switch AND the per-token flag must be on for a write.

SET NAMES utf8mb4;
SET time_zone = '+00:00';

ALTER TABLE api_tokens
    ADD COLUMN can_write TINYINT(1) NOT NULL DEFAULT 0 AFTER list_type;

INSERT INTO settings (key_name, value) VALUES
    ('enable_write_api', '0')
ON DUPLICATE KEY UPDATE key_name = key_name;
