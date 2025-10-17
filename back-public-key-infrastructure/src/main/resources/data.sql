-- Insert sample organizations
INSERT INTO organizations (id, name, description, contact_email, contact_phone, address, created_at, updated_at)
VALUES (1, 'Example Organization', 'Example organization for demo purposes', 'contact@example.org', '+1-555-0100', '123 Example Street', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO organizations (id, name, description, contact_email, contact_phone, address, created_at, updated_at)
VALUES (2, 'Test Corp', 'Second demo tenant', 'info@testcorp.org', '+1-555-0101', '456 Test Avenue', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO organizations (id, name, description, contact_email, contact_phone, address, created_at, updated_at)
VALUES (3, 'Demo Inc', 'Third tenant for seed data', 'hello@demoinc.org', '+1-555-0102', '789 Demo Road', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Insert admin user (password: admin123)
INSERT INTO users (id, email, password_hash, first_name, last_name, role, organization_id, enabled, email_confirmed, mfa_enabled, activation_token, token_expiration, mfa_secret, refresh_token, refresh_token_expires_at) 
VALUES (1, 'admin@example.com', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDi', 'Admin', 'User', 'ADMIN', 1, true, true, false, NULL, NULL, NULL, NULL, NULL);

-- Insert CA user (password: ca123)
INSERT INTO users (id, email, password_hash, first_name, last_name, role, organization_id, enabled, email_confirmed, mfa_enabled, activation_token, token_expiration, mfa_secret, refresh_token, refresh_token_expires_at) 
VALUES (2, 'ca@example.com', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDi', 'CA', 'Manager', 'CA_USER', 1, true, true, false, NULL, NULL, NULL, NULL, NULL);

-- Insert EE user (password: user123)
INSERT INTO users (id, email, password_hash, first_name, last_name, role, organization_id, enabled, email_confirmed, mfa_enabled, activation_token, token_expiration, mfa_secret, refresh_token, refresh_token_expires_at) 
VALUES (3, 'user@example.com', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDi', 'End', 'Entity', 'EE_USER', 1, true, true, false, NULL, NULL, NULL, NULL, NULL);

-- Insert additional admin user (password: admin456)
INSERT INTO users (id, email, password_hash, first_name, last_name, role, organization_id, enabled, email_confirmed, mfa_enabled, activation_token, token_expiration, mfa_secret, refresh_token, refresh_token_expires_at) 
VALUES (4, 'admin2@example.com', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDi', 'Super', 'Admin', 'ADMIN', 1, true, true, false, NULL, NULL, NULL, NULL, NULL);

-- Insert additional CA user (password: ca456)
INSERT INTO users (id, email, password_hash, first_name, last_name, role, organization_id, enabled, email_confirmed, mfa_enabled, activation_token, token_expiration, mfa_secret, refresh_token, refresh_token_expires_at) 
VALUES (5, 'ca2@example.com', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDi', 'Secondary', 'CA', 'CA_USER', 2, true, true, false, NULL, NULL, NULL, NULL, NULL);

-- Insert EE user (password: ee123)
INSERT INTO users (id, email, password_hash, first_name, last_name, role, organization_id, enabled, email_confirmed, mfa_enabled, activation_token, token_expiration, mfa_secret, refresh_token, refresh_token_expires_at) 
VALUES (6, 'ee@example.com', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDi', 'End', 'Entity', 'EE_USER', 1, true, true, false, NULL, NULL, NULL, NULL, NULL);
