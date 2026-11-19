<?php
/**
 * ==============================================================================
 * SECURE SYSTEM UTS - HYBRID CRYPTOGRAPHY & ZERO-KNOWLEDGE ARCHITECTURE
 * File: database.php (Koneksi Database MySQLi dengan Auto-Provisioning)
 * ==============================================================================
 */

// Konfigurasi Database Lokal Laragon
$db_host = 'localhost';
$db_user = 'root';
$db_pass = '';
$db_name = 'uts_keamanan';

// Nonaktifkan mode exception otomatis mysqli pada PHP 8.1+ agar error ditangani secara halus
mysqli_report(MYSQLI_REPORT_OFF);

// 1. Inisialisasi koneksi awal ke server MySQL
$conn = @new mysqli($db_host, $db_user, $db_pass);

// Pengecekan status koneksi ke MySQL server
if ($conn->connect_error) {
    die("
    <div style='font-family: Arial, sans-serif; padding: 25px; margin: 30px auto; max-width: 650px; background: #fff1f2; border: 1px solid #fecdd3; border-radius: 10px; color: #9f1239;'>
        <h3 style='margin-top: 0;'>⚠️ Koneksi MySQL Server Gagal</h3>
        <p>Tidak dapat terhubung ke MySQL di <code>{$db_host}</code>.</p>
        <p><strong>Pesan Error:</strong> <code>" . htmlspecialchars($conn->connect_error) . "</code></p>
        <hr style='border: 0; border-top: 1px solid #fecdd3;'>
        <p style='font-size: 14px; margin-bottom: 0;'>
            <strong>Petunjuk:</strong> Pastikan servis <strong>MySQL</strong> di Laragon sudah dalam status <strong>Started</strong>.
        </p>
    </div>
    ");
}

// 2. Buat database secara otomatis jika belum ada di Laragon
$conn->query("CREATE DATABASE IF NOT EXISTS `{$db_name}` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");

// 3. Pilih database uts_keamanan
if (!$conn->select_db($db_name)) {
    die("
    <div style='font-family: Arial, sans-serif; padding: 25px; margin: 30px auto; max-width: 650px; background: #fff1f2; border: 1px solid #fecdd3; border-radius: 10px; color: #9f1239;'>
        <h3 style='margin-top: 0;'>⚠️ Gagal Memilih Database</h3>
        <p>Tidak dapat mengakses database <strong>{$db_name}</strong>.</p>
        <p><strong>Pesan Error:</strong> <code>" . htmlspecialchars($conn->error) . "</code></p>
    </div>
    ");
}

// 4. Buat tabel data_rahasia secara otomatis jika belum ada
$sql_table = "CREATE TABLE IF NOT EXISTS `data_rahasia` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `judul` VARCHAR(100) NOT NULL COMMENT 'Judul Dokumen Rahasia',
    `konten_terenkripsi` LONGTEXT NOT NULL COMMENT 'Base64 Ciphertext AES-256-GCM',
    `aes_key_terenkripsi` TEXT NOT NULL COMMENT 'Base64 Kunci AES dienkripsi RSA',
    `aes_iv` VARCHAR(255) NOT NULL COMMENT 'Base64 IV 12-byte GCM',
    `aes_tag` VARCHAR(255) NOT NULL COMMENT 'Base64 Authentication Tag GCM',
    `waktu_dibuat` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

$conn->query($sql_table);

// 5. Set karakter encoding ke utf8mb4 untuk integritas data kriptografi
$conn->set_charset("utf8mb4");
