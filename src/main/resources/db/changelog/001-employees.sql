--liquibase formatted sql
--changeset cv-demo:001-employees
CREATE TABLE employees (
    id UUID PRIMARY KEY,
    employee_code VARCHAR(64) NOT NULL UNIQUE,
    full_name VARCHAR(160) NOT NULL,
    department VARCHAR(120),
    face_model VARCHAR(100) NOT NULL,
    face_embedding BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT employee_embedding_size CHECK (OCTET_LENGTH(face_embedding) = 512)
);
CREATE TABLE employee_registry_lock (id INTEGER PRIMARY KEY CHECK (id = 1));
INSERT INTO employee_registry_lock (id) VALUES (1);
--rollback DROP TABLE employee_registry_lock;
--rollback DROP TABLE employees;
