-- Insert sample organizations
INSERT INTO organizations (id, name) VALUES (1, 'Example Organization');
INSERT INTO organizations (id, name) VALUES (2, 'Test Corp');
INSERT INTO organizations (id, name) VALUES (3, 'Demo Inc');

-- Insert admin user (password: admin123)
INSERT INTO users (id, email, password_hash, first_name, last_name, role, organization_id, enabled, mfa_enabled) 
VALUES (1, 'admin@example.com', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDi', 'Admin', 'User', 'ADMIN', 1, true, false);

-- Insert CA user (password: ca123)
INSERT INTO users (id, email, password_hash, first_name, last_name, role, organization_id, enabled, mfa_enabled) 
VALUES (2, 'ca@example.com', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDi', 'CA', 'Manager', 'CA_USER', 1, true, false);

-- Insert regular user (password: user123)
INSERT INTO users (id, email, password_hash, first_name, last_name, role, organization_id, enabled, mfa_enabled) 
VALUES (3, 'user@example.com', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDi', 'Regular', 'User', 'REGULAR_USER', 1, true, false);
