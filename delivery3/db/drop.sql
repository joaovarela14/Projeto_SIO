-- Seleciona o banco de dados
USE repository;

-- Desabilita verificações de chaves estrangeiras
SET FOREIGN_KEY_CHECKS = 0;

-- Remove todas as tabelas
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS subject_organizations;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS subjects;

-- Reabilita verificações de chaves estrangeiras
SET FOREIGN_KEY_CHECKS = 1;
