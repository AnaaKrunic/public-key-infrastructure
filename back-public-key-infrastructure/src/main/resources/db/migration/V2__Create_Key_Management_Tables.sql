-- Migration script to create key management tables for enhanced security
-- This creates the master key and user key tables for the new key hierarchy

-- Create master_keys table
CREATE TABLE master_keys (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    encrypted_key TEXT NOT NULL,
    encryption_iv VARCHAR(24) NOT NULL,
    encryption_tag VARCHAR(24) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    last_rotated_at TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    version INTEGER NOT NULL DEFAULT 1
);

-- Create user_keys table
CREATE TABLE user_keys (
    user_id BIGINT PRIMARY KEY,
    encrypted_user_key TEXT NOT NULL,
    encryption_iv VARCHAR(24) NOT NULL,
    encryption_tag VARCHAR(24) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    last_rotated_at TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    version INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX idx_master_keys_active ON master_keys(active);
CREATE INDEX idx_master_keys_version ON master_keys(version);
CREATE INDEX idx_user_keys_active ON user_keys(active);
CREATE INDEX idx_user_keys_version ON user_keys(version);

-- Insert initial master key (encrypted with fallback key for development)
-- In production, this should be done through the application startup
INSERT INTO master_keys (encrypted_key, encryption_iv, encryption_tag, created_at, active, version)
VALUES (
    'encrypted_master_key_placeholder',
    'base64_iv_placeholder',
    'base64_tag_placeholder',
    CURRENT_TIMESTAMP,
    TRUE,
    1
);

-- Add comments for documentation
COMMENT ON TABLE master_keys IS 'Stores encrypted master keys used to encrypt user-specific keys';
COMMENT ON TABLE user_keys IS 'Stores encrypted user-specific keys used to encrypt private keys';

COMMENT ON COLUMN master_keys.encrypted_key IS 'Base64-encoded encrypted master key data';
COMMENT ON COLUMN master_keys.encryption_iv IS 'Base64-encoded initialization vector for master key encryption';
COMMENT ON COLUMN master_keys.encryption_tag IS 'Base64-encoded authentication tag for master key encryption';
COMMENT ON COLUMN master_keys.active IS 'Whether this master key is currently active (only one should be active)';
COMMENT ON COLUMN master_keys.version IS 'Version number for key rotation tracking';

COMMENT ON COLUMN user_keys.encrypted_user_key IS 'Base64-encoded encrypted user key data';
COMMENT ON COLUMN user_keys.encryption_iv IS 'Base64-encoded initialization vector for user key encryption';
COMMENT ON COLUMN user_keys.encryption_tag IS 'Base64-encoded authentication tag for user key encryption';
COMMENT ON COLUMN user_keys.active IS 'Whether this user key is currently active (only one per user should be active)';
COMMENT ON COLUMN user_keys.version IS 'Version number for key rotation tracking';
