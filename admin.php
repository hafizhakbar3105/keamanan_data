<?php
/**
 * ==============================================================================
 * DEFENSE CYBER SECURE SYSTEM - KEMENTERIAN PERTAHANAN
 * Hybrid Cryptography (AES-256-GCM + RSA-1024) & Zero-Knowledge Architecture
 * File: admin.php (Pusat Sandi Komando - Enkripsi & Dekripsi Berkas Intelijen)
 * ==============================================================================
 */

session_start();

// 1. MANAJEMEN LOGOUT (admin.php?logout=true)
if (isset($_GET['logout']) && $_GET['logout'] === 'true') {
    session_unset();
    session_destroy();
    header("Location: index.php");
    exit;
}

// 2. TANGKAP & BERSIHKAN PRIVATE KEY DARI POST index.php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['private_key'])) {
    $raw_key = $_POST['private_key'];
    // Bersihkan carriage return (\r\n -> \n) dan trim spasi kosong
    $cleaned_key = trim($raw_key);
    $cleaned_key = str_replace("\r\n", "\n", $cleaned_key);
    $_SESSION['private_key'] = $cleaned_key;
}

// 3. VALIDASI SESI: Jika session private_key kosong, redirect ke index.php
if (empty($_SESSION['private_key'])) {
    header("Location: index.php");
    exit;
}

// 4. KONEKSI DATABASE
require_once 'database.php';

// Variabel status notifikasi formulir
$alert_type = null;
$alert_msg  = null;

// Tangani aksi Hapus Dokumen
if (isset($_GET['hapus'])) {
    $id_hapus = (int)$_GET['hapus'];
    $stmt_del = $conn->prepare("DELETE FROM data_rahasia WHERE id = ?");
    if ($stmt_del) {
        $stmt_del->bind_param("i", $id_hapus);
        $stmt_del->execute();
        $stmt_del->close();
        header("Location: admin.php?msg=deleted");
        exit;
    }
}

if (isset($_GET['msg']) && $_GET['msg'] === 'deleted') {
    $alert_type = 'info';
    $alert_msg  = 'Berkas sandi berhasil dimusnahkan dari brankas database.';
}

// ==============================================================================
// LOGIKA DEKRIPSI REAL-TIME DENGAN SESSION PRIVATE KEY
// ==============================================================================
$active_private_key = $_SESSION['private_key'];
// Validasi objek Private Key secara halus menggunakan @
$priv_key_res = @openssl_pkey_get_private($active_private_key);

// Ambil pasangan Public Key dari Private Key sesi aktif untuk kemudahan auto-fill
$derived_pub_key = '';
if ($priv_key_res !== false) {
    $key_details = @openssl_pkey_get_details($priv_key_res);
    $derived_pub_key = $key_details['key'] ?? '';
}

// Ambil seluruh data dokumen diurutkan dari yang terbaru
$query = "SELECT * FROM data_rahasia ORDER BY id DESC";
$result = $conn->query($query);

$daftar_dokumen = [];
$total_dokumen = 0;
$total_terdekripsi = 0;
$total_terkunci = 0;

if ($result && $result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $total_dokumen++;
        $is_success = false;
        $plaintext_hasil = null;

        // Coba dekripsi hanya jika Private Key di sesi valid sintaksnya
        if ($priv_key_res !== false) {
            $raw_enc_aes_key = @base64_decode($row['aes_key_terenkripsi']);
            $decrypted_aes_key = "";

            // Buka Kunci AES dengan Private Key RSA
            $rsa_dec_ok = @openssl_private_decrypt($raw_enc_aes_key, $decrypted_aes_key, $priv_key_res);

            if ($rsa_dec_ok && strlen($decrypted_aes_key) === 32) {
                $raw_ciphertext = @base64_decode($row['konten_terenkripsi']);
                $raw_iv         = @base64_decode($row['aes_iv']);
                $raw_tag        = @base64_decode($row['aes_tag']);

                // Dekripsi konten menggunakan AES-256-GCM
                $decrypted_text = @openssl_decrypt(
                    $raw_ciphertext,
                    "aes-256-gcm",
                    $decrypted_aes_key,
                    OPENSSL_RAW_DATA,
                    $raw_iv,
                    $raw_tag
                );

                if ($decrypted_text !== false) {
                    $is_success = true;
                    $plaintext_hasil = $decrypted_text;
                }
            }
        }

        if ($is_success) {
            $total_terdekripsi++;
        } else {
            $total_terkunci++;
        }

        $row['is_decrypted'] = $is_success;
        $row['decrypted_text'] = $plaintext_hasil;
        $daftar_dokumen[] = $row;
    }
}

// ==============================================================================
// EVALUASI OTORISASI ZERO-KNOWLEDGE (KUNCI SAH vs PENYAMARAN INTELIJEN)
// ==============================================================================
// Kunci dianggap SAH (Authorized) jika pengguna memasukkan format RSA Private Key yang valid:
// Jika bukan format RSA (misal teks sembarang atau intruder), sistem akan masuk ke Mode Penyamaran (Decoy).
$is_authorized = ($priv_key_res !== false);

// ==============================================================================
// BAGIAN A: FORM TAMBAH DOKUMEN RAHASIA (HANYA JIKA AUTHORIZED)
// ==============================================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['simpan_dokumen'])) {
    if (!$is_authorized) {
        $alert_type = 'danger';
        $alert_msg  = 'Akses ditolak: Token sandi tidak terverifikasi.';
    } else {
        $judul        = trim($_POST['judul'] ?? '');
        $isi_dokumen  = trim($_POST['isi_dokumen'] ?? '');
        $raw_pub_key  = trim($_POST['public_key'] ?? '');
        $public_key   = str_replace("\r\n", "\n", $raw_pub_key);

        if (empty($judul) || empty($isi_dokumen) || empty($public_key)) {
            $alert_type = 'danger';
            $alert_msg  = 'Semua data komando (Klasifikasi Judul, Instruksi Sandi, dan Kunci Publik Penerima) wajib diisi!';
        } else {
            // Validasi Public Key RSA secara halus tanpa fatal error
            $pub_key_res = @openssl_pkey_get_public($public_key);
            
            if (!$pub_key_res) {
                $alert_type = 'danger';
                $alert_msg  = 'Kunci Publik RSA Satuan tidak valid! Pastikan format PEM lengkap dengan -----BEGIN PUBLIC KEY-----.';
            } else {
                // 1. Generate Kunci Simetris AES (256-bit / 32 bytes) & IV (12 bytes untuk GCM)
                $aes_key = random_bytes(32);
                $iv      = random_bytes(12);
                $tag     = "";

                // 2. Enkripsi isi dokumen menggunakan AES-256-GCM
                $ciphertext_raw = @openssl_encrypt(
                    $isi_dokumen,
                    "aes-256-gcm",
                    $aes_key,
                    OPENSSL_RAW_DATA,
                    $iv,
                    $tag
                );

                // 3. Enkripsi $aes_key menggunakan Public Key RSA
                $encrypted_aes_key_raw = "";
                $rsa_encrypt_success   = @openssl_public_encrypt($aes_key, $encrypted_aes_key_raw, $pub_key_res);

                // 4. Simpan ke database jika kedua proses enkripsi sukses
                if ($rsa_encrypt_success && $ciphertext_raw !== false && !empty($tag)) {
                    $konten_terenkripsi  = base64_encode($ciphertext_raw);
                    $aes_key_terenkripsi = base64_encode($encrypted_aes_key_raw);
                    $aes_iv              = base64_encode($iv);
                    $aes_tag             = base64_encode($tag);

                    $stmt = $conn->prepare("INSERT INTO data_rahasia (judul, konten_terenkripsi, aes_key_terenkripsi, aes_iv, aes_tag) VALUES (?, ?, ?, ?, ?)");
                    if ($stmt) {
                        $stmt->bind_param("sssss", $judul, $konten_terenkripsi, $aes_key_terenkripsi, $aes_iv, $aes_tag);
                        if ($stmt->execute()) {
                            $alert_type = 'success';
                            $alert_msg  = 'Berkas strategis militer berhasil dienkripsi secara Hybrid (AES-256-GCM + RSA) dan diamankan ke brankas database!';
                            header("Location: admin.php?msg=added");
                            exit;
                        } else {
                            $alert_type = 'danger';
                            $alert_msg  = 'Gagal menyimpan ke pangkalan data: ' . htmlspecialchars($stmt->error);
                        }
                        $stmt->close();
                    } else {
                        $alert_type = 'danger';
                        $alert_msg  = 'Gagal menyiapkan transmisi pangkalan data: ' . htmlspecialchars($conn->error);
                    }
                } else {
                    $alert_type = 'danger';
                    $alert_msg  = 'Gagal menjalankan protokol enkripsi sandi pertahanan.';
                }
            }
        }
    }
}

if (isset($_GET['msg']) && $_GET['msg'] === 'added') {
    $alert_type = 'success';
    $alert_msg  = 'Berkas strategis militer berhasil dienkripsi secara Hybrid (AES-256-GCM + RSA) dan diamankan ke brankas database!';
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= ($is_authorized ? 'Pusat Sandi Komando Pertahanan Negara - Kementerian Pertahanan' : 'RADAR_TELEMETRY_FEED_0x' . strtoupper(substr(md5($active_private_key), 0, 8))) ?></title>
    <!-- Google Fonts: Inter & Fira Code -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <!-- Bootstrap 5 CDN -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome 6 CDN -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --mil-dark: #0a0f1d;
            --mil-navy: #0f172a;
            --mil-card: #1e293b;
            --mil-gold: #f59e0b;
            --mil-red: #ef4444;
            --mil-cyan: #38bdf8;
            --bg-canvas: #f8fafc;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-canvas);
            background-image: 
                radial-gradient(at 0% 0%, rgba(15, 23, 42, 0.05) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(56, 189, 248, 0.06) 0px, transparent 50%);
            min-height: 100vh;
            color: #1e293b;
        }

        .font-monospace {
            font-family: 'Fira Code', monospace !important;
            font-size: 0.85rem;
            line-height: 1.5;
        }

        .navbar-custom {
            background-color: var(--mil-dark);
            border-bottom: 2px solid #1e293b;
            box-shadow: 0 4px 20px -2px rgba(10, 15, 29, 0.4);
        }

        .glass-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
            border: 1px solid rgba(203, 213, 225, 0.8);
            box-shadow: 0 10px 25px -5px rgba(15, 23, 42, 0.08);
            border-radius: 1rem;
        }

        .btn-navy {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #ffffff;
            border: 1px solid #334155;
            font-weight: 600;
        }

        .btn-navy:hover {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: #38bdf8;
            border-color: #38bdf8;
        }

        .doc-card {
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            border-left: 4px solid transparent;
        }

        .doc-card.success-border {
            border-left-color: #16a34a;
        }

        .doc-card.danger-border {
            border-left-color: #dc2626;
        }

        .content-box-plain {
            background-color: #f0fdf4;
            border: 1px solid #bbf7d0;
            color: #14532d;
            border-radius: 0.5rem;
            padding: 0.85rem 1rem;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .content-box-cipher {
            background-color: #0f172a;
            border: 1px solid #334155;
            color: #f87171;
            border-radius: 0.5rem;
            padding: 0.85rem 1rem;
            word-break: break-all;
        }

        .key-badge-preview {
            max-width: 250px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .badge-classification {
            background: linear-gradient(135deg, #b91c1c, #991b1b);
            color: #ffffff;
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.5px;
            padding: 0.25rem 0.6rem;
            border-radius: 0.3rem;
            text-transform: uppercase;
        }
    </style>
</head>
<body>

    <!-- ==================================================================== -->
    <!-- NAVBAR PUSAT KOMANDO PERTAHANAN                                      -->
    <!-- ==================================================================== -->
    <nav class="navbar navbar-expand-lg navbar-dark navbar-custom py-3 sticky-top">
        <div class="container-fluid px-lg-4">
            
            <?php if ($is_authorized): ?>
                <!-- Mode Terotorisasi (Personel Sah Kementerian Pertahanan) -->
                <a class="navbar-brand d-flex align-items-center gap-2 fw-bold" href="admin.php">
                    <span class="d-inline-flex align-items-center justify-content-center bg-danger text-white rounded-3 p-2 shadow-sm" style="width: 38px; height: 38px;">
                        <i class="fa-solid fa-shield-halved"></i>
                    </span>
                    <div>
                        <span class="text-white d-block lh-1 fs-5">KEMHAN <span class="text-info fw-normal">CYBER DEFENSE</span></span>
                        <span class="text-white-50 small" style="font-size: 0.7rem; letter-spacing: 0.5px;">PUSAT KOMANDO SANDI & BERKAS INTELIJEN</span>
                    </div>
                </a>
            <?php else: ?>
                <!-- Mode Penyamaran Total: Disguised as Passive Radar Telemetry Node -->
                <a class="navbar-brand d-flex align-items-center gap-2 fw-bold font-monospace text-secondary" href="admin.php">
                    <span class="d-inline-flex align-items-center justify-content-center bg-dark text-secondary rounded-3 p-2 border border-secondary" style="width: 38px; height: 38px;">
                        <i class="fa-solid fa-satellite-dish"></i>
                    </span>
                    <span class="small text-light">RADAR_NODE_0x<?= strtoupper(substr(md5($active_private_key), 0, 6)) ?> // PASSIVE_FREQUENCY_TELEMETRY</span>
                </a>
            <?php endif; ?>

            <!-- Sesi Personel & Tombol Tutup Akses -->
            <div class="d-flex align-items-center gap-2 flex-wrap ms-auto">
                
                <?php if ($is_authorized): ?>
                    <span class="badge-classification d-none d-xl-inline-block">
                        <i class="fa-solid fa-lock text-warning me-1"></i> TOP SECRET
                    </span>

                    <div class="d-none d-md-flex align-items-center gap-2 text-white-50 bg-dark px-3 py-1.5 rounded-pill border border-secondary small">
                        <i class="fa-solid fa-key text-success"></i>
                        <span class="text-light">Token Sesi:</span>
                        <span class="key-badge-preview font-monospace text-warning small">
                            <?= htmlspecialchars(substr($active_private_key, 0, 28)) ?>...
                        </span>
                        <button type="button" class="btn btn-sm btn-link text-info p-0 ms-1" data-bs-toggle="modal" data-bs-target="#activeKeyModal" title="Periksa Token Kunci Sesi">
                            <i class="fa-solid fa-eye"></i>
                        </button>
                    </div>

                    <!-- Tombol Keluar / Kunci Brankas -->
                    <a href="admin.php?logout=true" class="btn btn-danger btn-sm rounded-pill px-3 fw-semibold">
                        <i class="fa-solid fa-lock me-1"></i> Tutup Akses Komando
                    </a>
                <?php else: ?>
                    <!-- Penyamaran Tombol Exit tanpa membocorkan identitas militer -->
                    <a href="admin.php?logout=true" class="btn btn-outline-secondary btn-sm font-monospace rounded-pill px-3">
                        <i class="fa-solid fa-power-off me-1"></i> [DISCONNECT_FEED]
                    </a>
                <?php endif; ?>

            </div>
        </div>
    </nav>

    <!-- Main Container -->
    <div class="container-fluid px-lg-4 py-4">

        <!-- Banner Alert Operasi (Jika Ada) -->
        <?php if ($alert_msg && $is_authorized): ?>
            <div class="alert alert-<?= $alert_type ?> alert-dismissible fade show shadow-sm d-flex align-items-center gap-2 mb-4" role="alert">
                <i class="fa-solid <?= ($alert_type === 'success' ? 'fa-circle-check fs-5 text-success' : 'fa-circle-exclamation fs-5 text-danger') ?>"></i>
                <div><?= $alert_msg ?></div>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>

        <div class="row g-4">
            
            <!-- ================================================================ -->
            <!-- KOLOM KIRI (PANEL ENKRIPSI BERKAS PERTAHANAN)                    -->
            <!-- ================================================================ -->
            <div class="col-lg-4">
                
                <?php if ($is_authorized): ?>
                    <!-- FORM ASLI PERTAHANAN -->
                    <div class="card glass-card p-4 sticky-top" style="top: 85px; z-index: 10;">
                        
                        <div class="d-flex align-items-center justify-content-between mb-3">
                            <h5 class="fw-bold text-dark mb-0 d-flex align-items-center gap-2">
                                <span class="d-inline-flex p-2 bg-danger-subtle text-danger rounded-3">
                                    <i class="fa-solid fa-file-shield"></i>
                                </span>
                                Enkripsi Berkas Intelijen
                            </h5>
                            <span class="badge bg-dark text-warning border border-secondary font-monospace small">AES + RSA</span>
                        </div>

                        <p class="text-muted small mb-3">
                            Enkripsi instruksi strategis dengan <strong>AES-256-GCM</strong>, lalu bungkus kunci simetris dengan <strong>Kunci Publik RSA</strong> satuan penerima.
                        </p>

                        <form action="admin.php" method="POST">
                            <input type="hidden" name="simpan_dokumen" value="1">

                            <!-- Judul / Sandi Operasi -->
                            <div class="mb-3">
                                <label for="judul" class="form-label fw-semibold small text-dark">
                                    <i class="fa-solid fa-signature me-1 text-danger"></i> Klasifikasi / Judul Sandi Operasi:
                                </label>
                                <input 
                                    type="text" 
                                    name="judul" 
                                    id="judul" 
                                    class="form-control" 
                                    required 
                                    placeholder="Contoh: OPERASI_GARUDA // Patroli Natuna 2026">
                            </div>

                            <!-- Isi Dokumen (Plaintext) -->
                            <div class="mb-3">
                                <label for="isi_dokumen" class="form-label fw-semibold small text-dark">
                                    <i class="fa-solid fa-align-left me-1 text-danger"></i> Instruksi Strategis / Berkas Intelijen:
                                </label>
                                <textarea 
                                    name="isi_dokumen" 
                                    id="isi_dokumen" 
                                    class="form-control" 
                                    rows="5" 
                                    required 
                                    placeholder="Tuliskan koordinat posisi, rencana operasi, atau informasi rahasia komando..."></textarea>
                            </div>

                            <!-- Public Key RSA -->
                            <div class="mb-3">
                                <div class="d-flex justify-content-between align-items-center mb-1">
                                    <label for="public_key" class="form-label fw-semibold small text-dark mb-0">
                                        <i class="fa-solid fa-key me-1 text-danger"></i> Kunci Publik Satuan / Penerima:
                                    </label>
                                    <?php if (!empty($derived_pub_key)): ?>
                                        <button type="button" class="btn btn-sm btn-link text-primary p-0 text-decoration-none small" onclick="document.getElementById('public_key').value = <?= htmlspecialchars(json_encode($derived_pub_key)) ?>">
                                            <i class="fa-solid fa-wand-magic-sparkles me-1"></i> Auto-Fill Kunci Saya
                                        </button>
                                    <?php endif; ?>
                                </div>
                                <textarea 
                                    name="public_key" 
                                    id="public_key" 
                                    class="form-control font-monospace p-2" 
                                    rows="4" 
                                    required 
                                    style="background-color: #0f172a; color: #38bdf8; font-size: 0.78rem;" 
                                    placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"><?= htmlspecialchars($_POST['public_key'] ?? $derived_pub_key) ?></textarea>
                                <div class="form-text small text-muted">
                                    Kunci publik asimetris digunakan untuk membungkus kunci AES khusus untuk penerima.
                                </div>
                            </div>

                            <!-- Tombol Submit -->
                            <div class="d-grid mt-4">
                                <button type="submit" class="btn btn-navy py-2 d-flex align-items-center justify-content-center gap-2">
                                    <i class="fa-solid fa-shield-halved text-warning"></i>
                                    <span>ENKRIPSI & AMANKAN KE BRANKAS</span>
                                </button>
                            </div>
                        </form>

                    </div>

                <?php else: ?>
                    
                    <!-- PENYAMARAN TOTAL: TERLIHAT SEPERTI TERMINAL RADAR / TELEMETRI PASIF -->
                    <div class="card glass-card p-4 sticky-top bg-dark text-light border-secondary" style="top: 85px; z-index: 10;">
                        
                        <div class="d-flex align-items-center justify-content-between mb-3 font-monospace">
                            <span class="text-secondary small d-flex align-items-center gap-2">
                                <i class="fa-solid fa-circle-nodes text-danger"></i>
                                <span>RADAR_TELEMETRY_PIPELINE // 0x7B</span>
                            </span>
                            <span class="badge bg-secondary">PASSIVE</span>
                        </div>

                        <div class="font-monospace small text-secondary mb-3">
                            <span class="text-danger">[SIGNAL_INACTIVE]</span> RAW_SPECTRUM_LOG:
                        </div>

                        <div class="mb-3 font-monospace">
                            <label class="form-label small text-secondary">CARRIER_FREQUENCY:</label>
                            <input type="text" class="form-control bg-black text-secondary border-secondary font-monospace small" value="0x<?= strtoupper(substr(md5($active_private_key . 'freq'), 0, 20)) ?> // 7.42GHz" disabled readonly>
                        </div>

                        <div class="mb-3 font-monospace">
                            <label class="form-label small text-secondary">SPECTRUM_SAMPLE_BUFFER:</label>
                            <textarea class="form-control bg-black text-danger border-secondary font-monospace small" rows="5" disabled readonly><?= strtoupper(hash('sha512', $active_private_key . 'defense_radar')) ?>
<?= base64_encode(substr(hash('sha256', $active_private_key), 0, 32)) ?>
[SIGNAL_BLOCKED_UNAUTHORIZED]</textarea>
                        </div>

                        <div class="mb-3 font-monospace">
                            <label class="form-label small text-secondary">BASEBAND_TOKEN:</label>
                            <textarea class="form-control bg-black text-secondary border-secondary font-monospace small" rows="3" disabled readonly>-----BEGIN TELEMETRY DUMP-----
<?= substr(hash('sha256', $active_private_key . 'spec'), 0, 48) ?>...
-----END TELEMETRY DUMP-----</textarea>
                        </div>

                        <div class="d-grid mt-3">
                            <button type="button" class="btn btn-secondary font-monospace small" disabled>
                                [TRANSMITTER_OFFLINE_0x00]
                            </button>
                        </div>

                    </div>

                <?php endif; ?>

            </div>

            <!-- ================================================================ -->
            <!-- KOLOM KANAN (ARSIP BERKAS INTELIJEN & STATUS DEKRIPSI)           -->
            <!-- ================================================================ -->
            <div class="col-lg-8">
                
                <?php if ($is_authorized): ?>
                    
                    <?php if ($total_terdekripsi > 0): ?>
                        <!-- BANNER HIJAU RESMI: BERKAS BERHASIL DIDEKRIPSI -->
                        <div class="alert alert-success d-flex align-items-center shadow-sm py-3 px-4 border-0 mb-4 rounded-3" role="alert">
                            <i class="fa-solid fa-circle-check fs-2 text-success me-3"></i>
                            <div>
                                <h5 class="alert-heading fw-bold mb-1">Dekripsi Sah — Berkas Rahasia Negara Berhasil Dibuka.</h5>
                                <div class="small text-success-emphasis">
                                    Token Kunci Sandi personel valid dan berpasangan. Seluruh muatan <strong>AES-256-GCM</strong> berhasil diverifikasi integritasnya dan didekripsi ke teks komando asli.
                                </div>
                            </div>
                        </div>
                    <?php elseif ($total_dokumen > 0 && $total_terdekripsi === 0): ?>
                        <!-- BANNER KUNCI VALID NAMUN BERKAS LAIN MENGGUNAKAN KUNCI SATUAN BERBEDA -->
                        <div class="alert alert-warning d-flex align-items-center shadow-sm py-3 px-4 border-0 mb-4 rounded-3" role="alert">
                            <i class="fa-solid fa-shield-halved fs-2 text-warning me-3"></i>
                            <div>
                                <h5 class="alert-heading fw-bold mb-1">Kunci Personel Terverifikasi — Menunggu Dokumen Pasangan</h5>
                                <div class="small text-warning-emphasis">
                                    Kunci sandi Anda valid. Dokumen pada pangkalan data di bawah dienkripsi menggunakan kunci komando/satuan lain sehingga isinya tetap terkunci (Zero-Knowledge). Silakan tambahkan berkas baru menggunakan formulir di sebelah kiri.
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>

                    <!-- Heading Kolom Kanan Terotorisasi -->
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <div>
                            <h4 class="fw-bold text-dark mb-0 d-flex align-items-center gap-2">
                                <i class="fa-solid fa-folder-closed text-danger"></i> Arsip Berkas Intelijen & Dokumen Strategis
                            </h4>
                            <span class="text-muted small">Total Berkas: <strong><?= $total_dokumen ?></strong> (Didekripsi Real-Time oleh Server Sandi Pertahanan)</span>
                        </div>

                        <div class="d-flex gap-2">
                            <button onclick="window.location.reload();" class="btn btn-outline-secondary btn-sm rounded-pill px-3">
                                <i class="fa-solid fa-arrows-rotate me-1"></i> Perbarui Arsip
                            </button>
                        </div>
                    </div>

                <?php else: ?>
                    
                    <!-- BANNER PENYAMARAN (KUNCI SALAH / INTRUDER) -->
                    <div class="p-3 bg-dark text-secondary rounded-3 border border-secondary font-monospace small mb-4 shadow-sm">
                        <div class="d-flex align-items-center justify-content-between mb-1">
                            <span class="text-warning">
                                <i class="fa-solid fa-satellite me-2"></i>[PASSIVE_TELEMETRY_LOG]: UNCALIBRATED_CARRIER_WAVE
                            </span>
                            <span class="badge bg-secondary">STATUS: MASKED</span>
                        </div>
                        <div class="text-light-50">
                            STREAM_SESSION: 0x<?= strtoupper(substr(md5($active_private_key), 0, 16)) ?> // SPECTRUM_LOCKED
                        </div>
                        <div class="text-secondary small mt-1">
                            Sinyal tidak terkalibrasi. Seluruh blok data terkunci dalam status Zero-Knowledge Ciphertext.
                        </div>
                    </div>

                    <!-- Heading Penyamaran -->
                    <div class="d-flex justify-content-between align-items-center mb-3 font-monospace">
                        <span class="text-secondary fw-semibold">
                            RAW_FREQUENCY_BLOCKS [CHANNELS: <?= $total_dokumen ?>]
                        </span>
                        <span class="badge bg-dark border border-secondary text-secondary">ENCRYPTED_STATE</span>
                    </div>

                <?php endif; ?>

                <!-- DAFTAR DOKUMEN LOOP -->
                <?php if ($total_dokumen === 0): ?>
                    <div class="card glass-card p-5 text-center text-muted">
                        <i class="fa-solid fa-folder-open display-4 mb-3 text-secondary"></i>
                        <h5 class="fw-bold text-dark">Belum Ada Berkas Strategis Terdaftar</h5>
                        <p class="small mb-3">Gunakan formulir di sebelah kiri untuk mengenkripsi dan mengamankan berkas intelijen pertama Anda.</p>
                    </div>
                <?php else: ?>
                    
                    <div class="d-flex flex-column gap-3">
                        <?php foreach ($daftar_dokumen as $doc): ?>
                            
                            <?php if ($is_authorized): ?>
                                
                                <!-- ===================================================== -->
                                <!-- BERKAS VIEW MODE: PERSONEL SAH                      -->
                                <!-- ===================================================== -->
                                <div class="card glass-card p-4 doc-card <?= ($doc['is_decrypted'] ? 'success-border' : 'danger-border') ?>">
                                    
                                    <div class="d-flex justify-content-between align-items-start flex-wrap gap-2 mb-3">
                                        <div>
                                            <div class="d-flex align-items-center gap-2">
                                                <h5 class="fw-bold text-dark mb-0">
                                                    <?= ($doc['is_decrypted'] ? htmlspecialchars($doc['judul']) : '<code class="text-danger">ENC_BERKAS_MIL_0x' . strtoupper(substr(hash('sha256', $doc['id'] . $doc['judul']), 0, 16)) . '</code>') ?>
                                                </h5>
                                                <span class="badge bg-light text-muted border small">#<?= $doc['id'] ?></span>
                                            </div>
                                            <span class="text-muted small">
                                                <i class="fa-regular fa-clock me-1"></i> Waktu Registrasi: <?= htmlspecialchars($doc['waktu_dibuat']) ?>
                                            </span>
                                        </div>

                                        <div>
                                            <?php if ($doc['is_decrypted']): ?>
                                                <span class="badge bg-success-subtle text-success border border-success-subtle px-3 py-2 fw-semibold">
                                                    <i class="fa-solid fa-shield-check me-1"></i> Dekripsi Sah &bull; Berkas Terbaca
                                                </span>
                                            <?php else: ?>
                                                <span class="badge bg-danger-subtle text-danger border border-danger-subtle px-3 py-2 fw-semibold">
                                                    <i class="fa-solid fa-lock me-1"></i> Terenkripsi Sandi Satuan Lain
                                                </span>
                                            <?php endif; ?>
                                        </div>
                                    </div>

                                    <!-- Isi Dokumen -->
                                    <div class="mb-3">
                                        <label class="form-label small fw-semibold text-secondary mb-1">
                                            <?= ($doc['is_decrypted'] ? 'Instruksi Sandi Terbuka (Plaintext):' : 'Muatan Terenkripsi Sandi Militer (Ciphertext Database):') ?>
                                        </label>
                                        
                                        <?php if ($doc['is_decrypted']): ?>
                                            <div class="content-box-plain font-monospace">
                                                <?= htmlspecialchars($doc['decrypted_text']) ?>
                                            </div>
                                        <?php else: ?>
                                            <div class="content-box-cipher">
                                                <code class="text-danger font-monospace fs-6">
                                                    <?= htmlspecialchars(substr($doc['konten_terenkripsi'], 0, 40)) ?>...
                                                </code>
                                                <span class="badge bg-danger text-white ms-2 small">Terkunci</span>
                                            </div>
                                        <?php endif; ?>
                                    </div>

                                    <!-- Action bar -->
                                    <div class="d-flex justify-content-between align-items-center pt-2 border-top flex-wrap gap-2">
                                        <div class="small text-muted">
                                            Protokol: <strong>AES-256-GCM</strong> + <strong>RSA-1024 Militer</strong>
                                        </div>
                                        
                                        <div class="d-flex gap-2">
                                            <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-toggle="collapse" data-bs-target="#cryptoDetail-<?= $doc['id'] ?>" aria-expanded="false">
                                                <i class="fa-solid fa-fingerprint me-1"></i> Detail Vektor & Tag GCM
                                            </button>
                                            
                                            <a href="admin.php?hapus=<?= $doc['id'] ?>" class="btn btn-outline-danger btn-sm" onclick="return confirm('Peringatan Keamanan: Apakah Anda yakin ingin memusnahkan berkas sandi ini dari database?');">
                                                <i class="fa-solid fa-trash-can"></i> Musnahkan
                                            </a>
                                        </div>
                                    </div>

                                    <!-- Collapse Detail Kriptografi -->
                                    <div class="collapse mt-3" id="cryptoDetail-<?= $doc['id'] ?>">
                                        <div class="p-3 bg-dark text-light rounded-3 font-monospace small">
                                            <div class="mb-2">
                                                <span class="text-secondary d-block">1. Initialization Vector (IV 12-byte GCM):</span>
                                                <code class="text-info"><?= htmlspecialchars($doc['aes_iv']) ?></code>
                                            </div>
                                            <div class="mb-2">
                                                <span class="text-secondary d-block">2. Authentication Tag (Integritas 16-byte GCM):</span>
                                                <code class="text-warning"><?= htmlspecialchars($doc['aes_tag']) ?></code>
                                            </div>
                                            <div class="mb-2">
                                                <span class="text-secondary d-block">3. Encrypted AES Key (RSA Digital Envelope):</span>
                                                <code class="text-light text-break"><?= htmlspecialchars($doc['aes_key_terenkripsi']) ?></code>
                                            </div>
                                            <div>
                                                <span class="text-secondary d-block">4. Full Ciphertext Payload:</span>
                                                <code class="text-success text-break"><?= htmlspecialchars($doc['konten_terenkripsi']) ?></code>
                                            </div>
                                        </div>
                                    </div>

                                </div>

                            <?php else: ?>

                                <!-- ===================================================== -->
                                <!-- BERKAS VIEW MODE: PENYAMARAN TOTAL (INTRUDER)         -->
                                <!-- ===================================================== -->
                                <div class="card glass-card p-4 bg-dark text-light border-secondary">
                                    
                                    <div class="d-flex justify-content-between align-items-start flex-wrap gap-2 mb-3 font-monospace">
                                        <div>
                                            <div class="text-danger fw-bold fs-6">
                                                TELEMETRY_BAND_0x<?= strtoupper(substr(hash('sha256', $doc['id'] . $doc['judul']), 0, 24)) ?>
                                            </div>
                                            <span class="text-secondary small">
                                                CYCLE_INDEX: 0x<?= strtoupper(dechex(strtotime($doc['waktu_dibuat']))) ?> // CH_ID: 0x<?= strtoupper(dechex($doc['id'])) ?>
                                            </span>
                                        </div>

                                        <div>
                                            <span class="badge bg-secondary font-monospace">
                                                [CARRIER_LOCKED]
                                            </span>
                                        </div>
                                    </div>

                                    <div class="mb-3 font-monospace">
                                        <div class="text-secondary small mb-1">CARRIER_SIGNAL_DUMP:</div>
                                        <div class="p-3 bg-black rounded border border-secondary text-danger font-monospace text-break small">
                                            <?= htmlspecialchars(substr($doc['konten_terenkripsi'], 0, 75)) ?>... [SIGNAL_MASKED]
                                        </div>
                                    </div>

                                    <div class="d-flex justify-content-between align-items-center pt-2 border-top border-secondary small font-monospace text-secondary">
                                        <span>PASSIVE_FREQUENCY_CHANNEL</span>
                                        <span class="badge bg-black border border-secondary text-secondary">[SECURE_ZERO_KNOWLEDGE]</span>
                                    </div>

                                </div>

                            <?php endif; ?>

                        <?php endforeach; ?>
                    </div>

                <?php endif; ?>

            </div>

        </div>

    </div>

    <!-- Modal Lihat Sesi Kunci Personel -->
    <?php if ($is_authorized): ?>
        <div class="modal fade" id="activeKeyModal" tabindex="-1" aria-labelledby="activeKeyModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered modal-lg">
                <div class="modal-content">
                    <div class="modal-header bg-dark text-white border-secondary">
                        <h5 class="modal-title d-flex align-items-center gap-2" id="activeKeyModalLabel">
                            <i class="fa-solid fa-key text-warning"></i> Token Kunci Sandi Personel (Sesi Aktif)
                        </h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body bg-dark text-light">
                        <p class="small text-secondary mb-2">
                            Token Kunci Pribadi (RSA Private Key) disimpan sementara di dalam memori sesi server untuk proses dekripsi dokumen secara lokal dan tidak pernah disimpan di database:
                        </p>
                        <textarea class="form-control font-monospace p-3 text-info bg-black border-secondary" rows="12" readonly onclick="this.select()"><?= htmlspecialchars($active_private_key) ?></textarea>
                        
                        <div class="mt-3 small">
                            <strong class="text-secondary">Validitas Asimetris:</strong>
                            <span class="badge bg-success ms-1"><i class="fa-solid fa-shield-check me-1"></i> Valid RSA Private Key Military Spec</span>
                        </div>
                    </div>
                    <div class="modal-footer bg-dark border-secondary">
                        <a href="admin.php?logout=true" class="btn btn-danger btn-sm">
                            <i class="fa-solid fa-power-off me-1"></i> Tutup Akses Sesi
                        </a>
                        <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Tutup</button>
                    </div>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <!-- Bootstrap 5 JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
