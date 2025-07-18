-- Creating table for Role entity
--CREATE TABLE role (
--    id BIGINT PRIMARY KEY AUTO_INCREMENT,
--    role VARCHAR(255) NOT NULL,
--    CONSTRAINT uk_role UNIQUE (role)
--);
--
---- Creating table for User entity
--CREATE TABLE user (
--    id BIGINT PRIMARY KEY AUTO_INCREMENT,
--    email VARCHAR(255) NOT NULL,
--    password VARCHAR(255) NOT NULL,
--    CONSTRAINT uk_email UNIQUE (email)
--);
--
---- Creating table for Session entity
--CREATE TABLE session (
--    id BIGINT PRIMARY KEY AUTO_INCREMENT,
--    token VARCHAR(255) NOT NULL,
--    login_at DATETIME NOT NULL,
--    expiring_at DATETIME NOT NULL,
--    user_id BIGINT NOT NULL,
--    session_status ENUM('ENDED', 'ACTIVE') NOT NULL,
--    CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
--);
--
---- Creating join table for User-Role many-to-many relationship
--CREATE TABLE user_roles (
--    user_id BIGINT NOT NULL,
--    role_id BIGINT NOT NULL,
--    PRIMARY KEY (user_id, role_id),
--    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
--    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES role(id) ON DELETE CASCADE
--);
