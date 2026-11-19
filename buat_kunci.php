<?php
/**
 * ==============================================================================
 * DEFENSE CYBER SECURE SYSTEM - KEMENTERIAN PERTAHANAN
 * Hybrid Cryptography (AES-256-GCM + RSA-1024) & Zero-Knowledge Architecture
 * File: buat_kunci.php (Pusat Penerbitan Sandi Asimetris Militer)
 * ==============================================================================
 */

session_start();

// 1. Deteksi otomatis lokasi file openssl.cnf untuk Laragon / Windows
$possible_cnf_paths = [
    'C:/laragon/usr/ssl/openssl.cnf',
    'C:/laragon/etc/ssl/openssl.cnf',
    (function_exists('php_ini_loaded_file') && php_ini_loaded_file() ? dirname(php_ini_loaded_file()) . '/extras/ssl/openssl.cnf' : '')
];

$detected_cnf = null;
foreach ($possible_cnf_paths as $path) {
    if (!empty($path) && file_exists($path)) {
        $detected_cnf = $path;
        break;
    }
}

// 2. Konfigurasi OpenSSL untuk RSA-1024
$config = [
    'digest_alg'       => 'sha256',
    'private_key_bits' => 1024,
    'private_key_type' => OPENSSL_KEYTYPE_RSA
];

if ($detected_cnf) {
    $config['config'] = $detected_cnf;
}

// 3. Generate pasangan kunci RSA (Disimpan di session agar tidak berubah saat refresh tidak sengaja)
$privKey = '';
$pubKey  = '';
$errorMsg = null;

if (empty($_SESSION['cached_priv_key']) || empty($_SESSION['cached_pub_key']) || isset($_GET['baru'])) {
    $res = @openssl_pkey_new($config);
    if ($res === false) {
        $errorMsg = "Gagal membuat kunci RSA: " . openssl_error_string();
    } else {
        // Export Private Key (Wajib menyertakan $config di parameter ke-4)
        $export_success = @openssl_pkey_export($res, $privKey, null, $config);
        if (!$export_success) {
            $errorMsg = "Gagal mengekspor Private Key: " . openssl_error_string();
        } else {
            // Ambil Public Key
            $details = openssl_pkey_get_details($res);
            $pubKey  = $details['key'] ?? '';
            
            // Simpan ke sesi agar kunci tetap sinkron saat pengguna berpindah tab
            $_SESSION['cached_priv_key'] = $privKey;
            $_SESSION['cached_pub_key']  = $pubKey;
        }
    }
} else {
    // Gunakan kunci yang sudah ada di sesi sehingga tidak berubah tanpa sengaja
    $privKey = $_SESSION['cached_priv_key'];
    $pubKey  = $_SESSION['cached_pub_key'];
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penerbitan Kunci Sandi Asimetris - Kementerian Pertahanan</title>
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
            --accent-blue: #38bdf8;
            --accent-blue-hover: #0284c7;
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
            font-size: 0.84rem;
            line-height: 1.5;
        }

        .navbar-custom {
            background-color: var(--mil-dark);
            border-bottom: 2px solid #1e293b;
            box-shadow: 0 4px 20px -2px rgba(10, 15, 29, 0.4);
        }

        .glass-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(203, 213, 225, 0.85);
            box-shadow: 0 10px 30px -5px rgba(15, 23, 42, 0.06);
            border-radius: 1rem;
        }

        .key-box {
            background-color: #0a0f1d;
            color: #f1f5f9;
            border: 1px solid #334155;
            border-radius: 0.5rem;
            resize: none;
            transition: all 0.2s ease-in-out;
        }

        .key-box:focus {
            background-color: #050811;
            color: #38bdf8;
            border-color: #38bdf8;
            box-shadow: 0 0 0 0.25rem rgba(56, 189, 248, 0.2);
            outline: none;
        }

        .badge-rsa {
            background: linear-gradient(135deg, #0f172a, #1e293b);
            color: #38bdf8;
            border: 1px solid #334155;
            padding: 0.4rem 0.8rem;
            font-weight: 600;
        }

        .btn-navy {
            background-color: var(--mil-navy);
            color: #ffffff;
            border: 1px solid #334155;
            font-weight: 500;
        }

        .btn-navy:hover {
            background-color: #1e293b;
            color: #38bdf8;
            border-color: #38bdf8;
        }

        .info-pill {
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            color: #1e40af;
            border-radius: 0.5rem;
            padding: 0.75rem 1rem;
        }
    </style>
</head>
<body>

    <!-- Header / Navbar Militer -->
    <nav class="navbar navbar-expand-lg navbar-dark navbar-custom py-3">
        <div class="container">
            <a class="navbar-brand d-flex align-items-center gap-2 fw-bold" href="index.php">
                <span class="d-inline-flex align-items-center justify-content-center bg-danger text-white rounded-3 p-2 shadow-sm" style="width: 38px; height: 38px;">
                    <i class="fa-solid fa-shield-halved"></i>
                </span>
                <div>
                    <span class="text-white d-block lh-1 fs-5">KEMHAN <span class="text-info fw-normal">CYBER DEFENSE</span></span>
                    <span class="text-white-50 small" style="font-size: 0.7rem; letter-spacing: 0.5px;">DIREKTORAT PENGAMANAN SANDI & INFORMASI STRATEGIS</span>
                </div>
            </a>
            <div class="d-flex align-items-center gap-2">
                <a href="index.php" class="btn btn-outline-light btn-sm px-3 rounded-pill">
                    <i class="fa-solid fa-arrow-left me-1"></i> Ke Gerbang Otentikasi
                </a>
            </div>
        </div>
    </nav>

    <!-- Main Container -->
    <div class="container py-5">
        <div class="row justify-content-center">
            <div class="col-lg-10">

                <!-- Heading Banner -->
                <div class="d-flex flex-column flex-md-row justify-content-between align-items-md-center gap-3 mb-4">
                    <div>
                        <div class="d-flex align-items-center gap-2 mb-1">
                            <h2 class="h3 fw-bold text-dark mb-0">Pusat Penerbitan Sandi Asimetris RSA-1024</h2>
                            <span class="badge badge-rsa rounded-pill"><i class="fa-solid fa-user-secret me-1"></i> Utilitas Sandi Militer</span>
                        </div>
                        <p class="text-muted mb-0">
                            Penerbitan pasangan kunci kriptografis untuk transmisi dokumen rahasia pertahanan negara (RSA-1024 Envelope + AES-256-GCM).
                        </p>
                    </div>
                    <div class="d-flex gap-2">
                        <a href="buat_kunci.php?baru=1" class="btn btn-navy rounded-pill px-3 py-2 shadow-sm">
                            <i class="fa-solid fa-arrows-rotate me-1"></i> Terbitkan Kunci Baru
                        </a>
                    </div>
                </div>

                <!-- Banner Informasi Akses Rahasia -->
                <div class="p-3 bg-dark text-light rounded-3 mb-4 d-flex align-items-center justify-content-between small border border-secondary shadow-sm">
                    <div>
                        <i class="fa-solid fa-eye-slash text-warning me-2"></i>
                        <span class="fw-semibold text-warning">Endpoint Sandi Terbatas:</span>
                        <span class="text-light-50">Halaman ini bersifat internal administrator sandi dan tidak dipublikasikan di menu depan demi integritas Zero-Knowledge.</span>
                    </div>
                    <span class="badge bg-secondary font-monospace">KLASIFIKASI: TERBATAS</span>
                </div>

                <!-- Info Alert OpenSSL Config -->
                <div class="info-pill d-flex align-items-start gap-3 mb-4 shadow-sm">
                    <i class="fa-solid fa-circle-info fs-5 mt-1 text-primary"></i>
                    <div class="small">
                        <strong>Modul Kriptografi Server Sandi (Laragon / Windows OpenSSL):</strong><br>
                        <?php if ($detected_cnf): ?>
                            <span class="text-success"><i class="fa-solid fa-check-circle me-1"></i> Konfigurasi OpenSSL Militer aktif:</span>
                            <code class="text-dark bg-white px-2 py-0.5 rounded border"><?= htmlspecialchars($detected_cnf) ?></code>
                        <?php else: ?>
                            <span class="text-warning"><i class="fa-solid fa-triangle-exclamation me-1"></i> Menggunakan pustaka internal bawaan PHP OpenSSL.</span>
                        <?php endif; ?>
                    </div>
                </div>

                <?php if ($errorMsg): ?>
                    <div class="alert alert-danger shadow-sm border-0 d-flex align-items-center gap-3" role="alert">
                        <i class="fa-solid fa-circle-exclamation fs-4"></i>
                        <div><?= htmlspecialchars($errorMsg) ?></div>
                    </div>
                <?php else: ?>

                    <div class="row g-4">
                        <!-- Private Key Card -->
                        <div class="col-md-6">
                            <div class="card glass-card h-100 p-4">
                                <div class="d-flex justify-content-between align-items-center mb-3">
                                    <div>
                                        <h5 class="fw-bold mb-0 text-danger d-flex align-items-center gap-2">
                                            <i class="fa-solid fa-key"></i> Token Sandi Pribadi (Private Key)
                                        </h5>
                                        <span class="small text-muted">Kunci Rahasia Personel (Login & Dekripsi Berkas)</span>
                                    </div>
                                    <span class="badge bg-danger text-white px-2 py-1 small">
                                        SANGAT RAHASIA
                                    </span>
                                </div>

                                <p class="text-muted small mb-2">
                                    Pegang kunci ini secara rahasia. Jangan dibagikan kepada siapapun. Gunakan kunci ini untuk otentikasi di gerbang komando.
                                </p>

                                <div class="position-relative mb-3">
                                    <textarea id="privKeyArea" class="form-control key-box font-monospace p-3" rows="12" readonly onclick="this.select()"><?= htmlspecialchars($privKey) ?></textarea>
                                </div>

                                <div class="d-flex gap-2 mt-auto">
                                    <button type="button" class="btn btn-outline-danger btn-sm w-100 fw-semibold" onclick="salinTeks('privKeyArea', this)">
                                        <i class="fa-regular fa-copy me-1"></i> Salin Token Private Key
                                    </button>
                                    <button type="button" class="btn btn-light btn-sm border" title="Download file PEM" onclick="downloadFile('personel_private_key.pem', document.getElementById('privKeyArea').value)">
                                        <i class="fa-solid fa-download"></i>
                                    </button>
                                </div>
                            </div>
                        </div>

                        <!-- Public Key Card -->
                        <div class="col-md-6">
                            <div class="card glass-card h-100 p-4">
                                <div class="d-flex justify-content-between align-items-center mb-3">
                                    <div>
                                        <h5 class="fw-bold mb-0 text-primary d-flex align-items-center gap-2">
                                            <i class="fa-solid fa-satellite-dish"></i> Kunci Publik Satuan (Public Key)
                                        </h5>
                                        <span class="small text-muted">Kunci Distribusi (Untuk Membungkus Kunci AES)</span>
                                    </div>
                                    <span class="badge bg-primary-subtle text-primary border border-primary-subtle px-2 py-1">
                                        DISTRIBUSI
                                    </span>
                                </div>

                                <p class="text-muted small mb-2">
                                    Dapat dibagikan ke satuan komando lain yang ingin mengirimkan berkas rahasia secara aman kepada Anda.
                                </p>

                                <div class="position-relative mb-3">
                                    <textarea id="pubKeyArea" class="form-control key-box font-monospace p-3" rows="12" readonly onclick="this.select()"><?= htmlspecialchars($pubKey) ?></textarea>
                                </div>

                                <div class="d-flex gap-2 mt-auto">
                                    <button type="button" class="btn btn-outline-primary btn-sm w-100 fw-semibold" onclick="salinTeks('pubKeyArea', this)">
                                        <i class="fa-regular fa-copy me-1"></i> Salin Kunci Publik Satuan
                                    </button>
                                    <button type="button" class="btn btn-light btn-sm border" title="Download file PEM" onclick="downloadFile('satuan_public_key.pem', document.getElementById('pubKeyArea').value)">
                                        <i class="fa-solid fa-download"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Panduan Alur Dokumen Intelijen -->
                    <div class="card glass-card p-4 mt-4">
                        <h6 class="fw-bold text-dark d-flex align-items-center gap-2 mb-3">
                            <i class="fa-solid fa-shield-halved text-danger"></i> Protokol Operasi Pengamanan Dokumen Negara:
                        </h6>
                        <div class="row g-3 small text-secondary">
                            <div class="col-md-4">
                                <div class="p-3 bg-light rounded-3 border h-100">
                                    <span class="fw-bold text-dark d-block mb-1">1. Otentikasi Personel</span>
                                    Salin <strong>Private Key</strong> untuk masuk ke gerbang sistem <code>index.php</code>. Server tidak menyimpan password apapun.
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="p-3 bg-light rounded-3 border h-100">
                                    <span class="fw-bold text-dark d-block mb-1">2. Enkripsi Sandi Intelijen</span>
                                    Gunakan <strong>Public Key</strong> satuan tujuan untuk mengenkripsi berkas operasional dengan AES-256-GCM.
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="p-3 bg-light rounded-3 border h-100">
                                    <span class="fw-bold text-dark d-block mb-1">3. Uji Penyamaran Radar</span>
                                    Masukkan kunci acak/salah &rarr; sistem otomatis menyamar menjadi aliran sinyal telemetri radar pasif tanpa membocorkan identitas komando militer.
                                </div>
                            </div>
                        </div>
                    </div>

                <?php endif; ?>

            </div>
        </div>
    </div>

    <!-- Bootstrap 5 JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function salinTeks(elementId, btnElement) {
            const textarea = document.getElementById(elementId);
            textarea.select();
            navigator.clipboard.writeText(textarea.value).then(() => {
                const originalHtml = btnElement.innerHTML;
                btnElement.innerHTML = '<i class="fa-solid fa-check me-1"></i> Tersalin!';
                btnElement.classList.remove('btn-outline-danger', 'btn-outline-primary');
                btnElement.classList.add('btn-success');
                setTimeout(() => {
                    btnElement.innerHTML = originalHtml;
                    btnElement.classList.remove('btn-success');
                    if (elementId === 'privKeyArea') {
                        btnElement.classList.add('btn-outline-danger');
                    } else {
                        btnElement.classList.add('btn-outline-primary');
                    }
                }, 2000);
            }).catch(err => {
                alert('Gagal menyalin otomatis, silakan seleksi teks secara manual.');
            });
        }

        function downloadFile(filename, text) {
            const element = document.createElement('a');
            element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
            element.setAttribute('download', filename);
            element.style.display = 'none';
            document.body.appendChild(element);
            element.click();
            document.body.removeChild(element);
        }
    </script>
</body>
</html>
