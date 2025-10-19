-- Insert admin user (password: admin123)
INSERT INTO users (email, password_hash, first_name, last_name, role, organization, enabled, email_confirmed, mfa_enabled, activation_token, token_expiration, mfa_secret, refresh_token, refresh_token_expires_at) 
VALUES ('admin@example.com', '$2a$10$52Ks2c5T2FzoG2LQnr3A/eyMDQVenzO0pjCbUsBtA9XQ/T81Ch30i', 'Admin', 'User', 'ADMIN', 'Example Organization', true, true, false, NULL, NULL, NULL, NULL, NULL);

-- Insert CA user (password: ca123)
INSERT INTO users (email, password_hash, first_name, last_name, role, organization, enabled, email_confirmed, mfa_enabled, activation_token, token_expiration, mfa_secret, refresh_token, refresh_token_expires_at) 
VALUES ('ca@example.com', '$2a$10$anKKjq9/VSFwWlOeq3In0OEpOfHcKlB.aC10YPsHk12oJqfwEJJN.', 'CA', 'Manager', 'CA_USER', 'Example Organization', true, true, false, NULL, NULL, NULL, NULL, NULL);

-- Insert EE user (password: user123)
INSERT INTO users (email, password_hash, first_name, last_name, role, organization, enabled, email_confirmed, mfa_enabled, activation_token, token_expiration, mfa_secret, refresh_token, refresh_token_expires_at) 
VALUES ('user@example.com', '$2a$10$b8fEjn23UUJnU0NWZ6yEP.B12opSszj.6pMYEwxUl1ERdb1vwpb7S', 'End', 'Entity', 'EE_USER', 'Example Organization', true, true, false, NULL, NULL, NULL, NULL, NULL);

-- Insert additional admin user (password: admin456)
INSERT INTO users (email, password_hash, first_name, last_name, role, organization, enabled, email_confirmed, mfa_enabled, activation_token, token_expiration, mfa_secret, refresh_token, refresh_token_expires_at) 
VALUES ('admin2@example.com', '$2a$10$f1B3PWR8W2xMKPDyguh5IOgvmNt9zy2PVMpwKQaYp1tCmxxufFAo2', 'Super', 'Admin', 'ADMIN', 'Example Organization', true, true, false, NULL, NULL, NULL, NULL, NULL);

-- Insert additional CA user (password: ca456)
INSERT INTO users (email, password_hash, first_name, last_name, role, organization, enabled, email_confirmed, mfa_enabled, activation_token, token_expiration, mfa_secret, refresh_token, refresh_token_expires_at) 
VALUES ('ca2@example.com', '$2a$10$/ucBFYV4un4UNXt6AFipS.OPTKkr.ysAtGUjZHcWJwPQGng04jF/K', 'Secondary', 'CA', 'CA_USER', 'Test Corp', true, true, false, NULL, NULL, NULL, NULL, NULL);

-- Insert EE user (password: ee123)
INSERT INTO users (email, password_hash, first_name, last_name, role, organization, enabled, email_confirmed, mfa_enabled, activation_token, token_expiration, mfa_secret, refresh_token, refresh_token_expires_at) 
VALUES ('ee@example.com', '$2a$10$5X8LPYjHQ.5vC2s4ShYL7eUjhMq1FwjSJk4Y5/m096XZ10VrUybbK', 'End', 'Entity', 'EE_USER', 'Example Organization', true, true, false, NULL, NULL, NULL, NULL, NULL);
