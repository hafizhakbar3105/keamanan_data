<?php
/**
 * ==============================================================================
 * DEFENSE CYBER SECURE SYSTEM - KEMENTERIAN PERTAHANAN
 * Hybrid Cryptography (AES-256-GCM + RSA-1024) & Zero-Knowledge Architecture
 * File: index.php (Gerbang Otentikasi Kriptografis Berkas Intelijen)
 * ==============================================================================
 */
session_start();

// Cek apakah personel sudah memiliki sesi Kunci Privat aktif
$has_session = !empty($_SESSION['private_key']);
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Portal Pengamanan Sandi & Dokumen Intelijen Pertahanan Negara</title>
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
            --mil-green: #10b981;
            --mil-cyan: #38bdf8;
            --bg-canvas: #f8fafc;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-canvas);
            background-image: 
                radial-gradient(at 0% 0%, rgba(15, 23, 42, 0.08) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(56, 189, 248, 0.08) 0px, transparent 50%);
            min-height: 100vh;
            color: #1e293b;
            display: flex;
            flex-direction: column;
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
            box-shadow: 0 20px 45px -15px rgba(15, 23, 42, 0.12);
            border-radius: 1.25rem;
        }

        .badge-classification {
            background: linear-gradient(135deg, #b91c1c, #991b1b);
            color: #ffffff;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.5px;
            padding: 0.35rem 0.75rem;
            border-radius: 0.35rem;
            text-transform: uppercase;
        }

        .badge-dept {
            background: rgba(56, 189, 248, 0.1);
            color: #0284c7;
            border: 1px solid rgba(56, 189, 248, 0.3);
            font-size: 0.8rem;
            font-weight: 600;
            padding: 0.4rem 0.85rem;
            border-radius: 2rem;
        }

        .key-input {
            background-color: #0a0f1d;
            color: #38bdf8;
            border: 1px solid #334155;
            border-radius: 0.75rem;
            resize: vertical;
            transition: all 0.25s ease-in-out;
        }

        .key-input:focus {
            background-color: #050811;
            color: #38bdf8;
            border-color: #38bdf8;
            box-shadow: 0 0 0 0.25rem rgba(56, 189, 248, 0.25);
            outline: none;
        }

        .key-input::placeholder {
            color: #475569;
            opacity: 0.85;
        }

        .btn-defense-submit {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #ffffff;
            border: 1px solid #334155;
            font-weight: 600;
            padding: 0.95rem 1.5rem;
            border-radius: 0.75rem;
            transition: all 0.2s ease-in-out;
            box-shadow: 0 4px 15px rgba(15, 23, 42, 0.25);
        }

        .btn-defense-submit:hover {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: #38bdf8;
            border-color: #38bdf8;
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(15, 23, 42, 0.35);
        }

        .feature-icon-box {
            width: 46px;
            height: 46px;
            border-radius: 0.75rem;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
        }
    </style>
</head>
<body>

    <!-- Header / Navbar Militer Pertahanan -->
    <nav class="navbar navbar-expand-lg navbar-dark navbar-custom py-3">
        <div class="container">
            <a class="navbar-brand d-flex align-items-center gap-2 fw-bold" href="index.php">
                <span class="d-inline-flex align-items-center justify-content-center bg-danger text-white rounded-3 p-2 shadow-sm" style="width: 40px; height: 40px;">
                    <i class="fa-solid fa-shield-halved"></i>
                </span>
                <div>
                    <span class="text-white d-block lh-1 fs-5">KEMHAN <span class="text-info fw-normal">CYBER DEFENSE</span></span>
                    <span class="text-white-50 small" style="font-size: 0.72rem; letter-spacing: 0.5px;">DIREKTORAT PENGAMANAN SANDI & INFORMASI STRATEGIS</span>
                </div>
            </a>
            
            <div class="d-flex align-items-center gap-2">
                <span class="badge-classification d-none d-sm-inline-flex align-items-center gap-1">
                    <i class="fa-solid fa-lock text-warning"></i> SANGAT RAHASIA / TOP SECRET
                </span>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container my-auto py-5">
        <div class="row justify-content-center align-items-center g-4">
            
            <!-- Left Info Panel (Deskripsi Dokumen Strategis Pertahanan) -->
            <div class="col-lg-5 col-md-10">
                <div class="pe-lg-4">
                    <div class="d-inline-flex align-items-center gap-2 badge-dept mb-3">
                        <i class="fa-solid fa-network-wired text-info"></i>
                        <span>Protokol Enkripsi Intelijen Sandi Militer</span>
                    </div>
                    
                    <h1 class="display-6 fw-bold text-dark mb-3">
                        Pusat Komando & Pengamanan Berkas Rahasia Negara
                    </h1>
                    
                    <p class="text-secondary mb-4">
                        Sistem Komando Pertahanan Nasional menerapkan standar kriptografi militer <strong>Zero-Knowledge</strong>. 
                        Server tidak menyimpan kata sandi master. Dokumen strategi pertahanan dan intelijen hanya dapat dibuka oleh personel yang memegang <strong>RSA Private Key</strong> terdaftar.
                    </p>

                    <!-- Fitur Pertahanan -->
                    <div class="d-flex flex-column gap-3 mb-4">
                        <div class="d-flex align-items-start gap-3">
                            <div class="feature-icon-box flex-shrink-0" style="background: #eff6ff; color: #1d4ed8;">
                                <i class="fa-solid fa-vault"></i>
                            </div>
                            <div>
                                <h6 class="fw-bold mb-1 text-dark">Enkripsi Berkas AES-256-GCM</h6>
                                <p class="small text-muted mb-0">Payload dokumen strategis dienkripsi dengan otentikasi tag 128-bit untuk mencegah sabotase dan kebocoran isi.</p>
                            </div>
                        </div>

                        <div class="d-flex align-items-start gap-3">
                            <div class="feature-icon-box flex-shrink-0" style="background: #fef2f2; color: #dc2626;">
                                <i class="fa-solid fa-envelope-shield"></i>
                            </div>
                            <div>
                                <h6 class="fw-bold mb-1 text-dark">Digital Envelope RSA-1024 Militer</h6>
                                <p class="small text-muted mb-0">Kunci simetris unik dibungkus langsung dengan Kunci Publik satuan/intelijen tujuan.</p>
                            </div>
                        </div>

                        <div class="d-flex align-items-start gap-3">
                            <div class="feature-icon-box flex-shrink-0" style="background: #f0fdf4; color: #15803d;">
                                <i class="fa-solid fa-shield-virus"></i>
                            </div>
                            <div>
                                <h6 class="fw-bold mb-1 text-dark">Anti-Penyadapan Berbasis Zero-Knowledge</h6>
                                <p class="small text-muted mb-0">Bahkan jika pangkalan data diretas musuh, seluruh data tersimpan dalam keadaan ciphertext yang mustahil dibuka tanpa kunci personel.</p>
                            </div>
                        </div>
                    </div>

                    <?php if ($has_session): ?>
                        <div class="p-3 bg-light border rounded-3 d-flex align-items-center justify-content-between mb-3 shadow-sm">
                            <div class="small">
                                <i class="fa-solid fa-circle-check text-success me-1"></i> Sesi Kunci Komando Aktif.
                            </div>
                            <a href="admin.php" class="btn btn-sm btn-outline-primary fw-semibold">
                                Masuk Ruang Sandi <i class="fa-solid fa-arrow-right ms-1"></i>
                            </a>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Right Login Form (Direct POST ke admin.php) -->
            <div class="col-lg-7 col-md-10">
                <div class="card glass-card p-4 p-md-5">
                    
                    <div class="d-flex justify-content-between align-items-start mb-4">
                        <div>
                            <span class="badge bg-danger-subtle text-danger border border-danger-subtle px-2 py-1 mb-2 fw-semibold">
                                <i class="fa-solid fa-key me-1"></i> VERIFIKASI IDENTITAS SANDI
                            </span>
                            <h3 class="fw-bold text-dark mb-1">Otentikasi Kunci Komando</h3>
                            <p class="text-muted small mb-0">
                                Masukkan Token RSA Private Key personel pertahanan untuk mengakses berkas intelijen.
                            </p>
                        </div>
                        <div class="d-none d-sm-block">
                            <span class="d-inline-flex align-items-center justify-content-center bg-dark text-warning rounded-circle shadow" style="width: 52px; height: 52px; border: 2px solid #334155;">
                                <i class="fa-solid fa-lock fs-5"></i>
                            </span>
                        </div>
                    </div>

                    <!-- FORM POST LANGSUNG KE admin.php -->
                    <form action="admin.php" method="POST" id="loginForm">
                        
                        <div class="mb-4">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <label for="private_key" class="form-label fw-bold text-dark mb-0 small">
                                    <i class="fa-solid fa-fingerprint me-1 text-primary"></i> Token Sandi Pribadi (RSA Private Key PEM):
                                </label>
                                <div class="d-flex gap-2">
                                    <button type="button" class="btn btn-sm btn-link text-decoration-none p-0 text-primary small" onclick="pasteKey()">
                                        <i class="fa-regular fa-clipboard me-1"></i> Tempel dari Clipboard
                                    </button>
                                    <span class="text-muted">|</span>
                                    <button type="button" class="btn btn-sm btn-link text-decoration-none p-0 text-secondary small" onclick="document.getElementById('private_key').value='';">
                                        Bersihkan
                                    </button>
                                </div>
                            </div>

                            <textarea 
                                name="private_key" 
                                id="private_key" 
                                class="form-control key-input font-monospace p-3" 
                                rows="10" 
                                required 
                                placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;MIICXAIBAAKCAQEA0x9...&#10;...&#10;-----END RSA PRIVATE KEY-----"></textarea>
                        </div>

                        <!-- Tombol Submit Otentikasi -->
                        <div class="d-grid">
                            <button type="submit" class="btn btn-defense-submit d-flex align-items-center justify-content-center gap-2">
                                <span>VERIFIKASI KUNCI SANDI & BUKA ARSIP</span>
                                <i class="fa-solid fa-arrow-right"></i>
                            </button>
                        </div>
                    </form>

                    <!-- Peringatan Hukum Kerahasiaan Negara -->
                    <div class="mt-4 pt-3 border-top text-muted small" style="font-size: 0.78rem;">
                        <div class="d-flex align-items-center justify-content-between text-secondary">
                            <span><i class="fa-solid fa-triangle-exclamation text-warning me-1"></i> DOKUMEN PERTAHANAN NEGARA</span>
                            <span>UU ITE &bull; SANDI NEGARA</span>
                        </div>
                        <p class="mb-0 mt-1 text-secondary opacity-75">
                            Akses tanpa hak ke dalam jaringan komando ini adalah tindak pidana keamanan negara. Seluruh percobaan akses dipantau secara kriptografis.
                        </p>
                    </div>

                </div>
            </div>

        </div>
    </div>

    <!-- Footer -->
    <footer class="mt-auto py-3 text-center text-muted small border-top bg-white">
        <div class="container">
            <span>Kementerian Pertahanan Republik Indonesia &bull; Sistem Sandi & Keamanan Berkas Intelijen &bull; Hybrid Cryptography Zero-Knowledge</span>
        </div>
    </footer>

    <!-- Bootstrap 5 JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        async function pasteKey() {
            try {
                const text = await navigator.clipboard.readText();
                if (text) {
                    document.getElementById('private_key').value = text;
                }
            } catch (err) {
                alert('Tidak dapat membaca clipboard otomatis. Silakan gunakan shortcut Ctrl+V pada kotak teks.');
            }
        }
    </script>
</body>
</html>
