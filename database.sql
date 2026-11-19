-- ==============================================================================
-- SECURE SYSTEM UTS - SISTEM INFORMASI HYBRID CRYPTOGRAPHY & ZERO-KNOWLEDGE
-- Database Schema: uts_keamanan
-- ==============================================================================

-- Buat database jika belum ada
CREATE DATABASE IF NOT EXISTS `uts_keamanan` 
    DEFAULT CHARACTER SET utf8mb4 
    COLLATE utf8mb4_unicode_ci;

USE `uts_keamanan`;

-- Buat tabel data_rahasia
CREATE TABLE IF NOT EXISTS `data_rahasia` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `judul` VARCHAR(100) NOT NULL COMMENT 'Judul Dokumen Rahasia',
    `konten_terenkripsi` LONGTEXT NOT NULL COMMENT 'Base64 Ciphertext hasil enkripsi AES-256-GCM',
    `aes_key_terenkripsi` TEXT NOT NULL COMMENT 'Base64 Kunci AES 256-bit yang dienkripsi dengan RSA Public Key',
    `aes_iv` VARCHAR(255) NOT NULL COMMENT 'Base64 Initialization Vector (12-byte untuk GCM)',
    `aes_tag` VARCHAR(255) NOT NULL COMMENT 'Base64 Authentication Tag GCM (16-byte)',
    `waktu_dibuat` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Waktu pembuatan dokumen'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
