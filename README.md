# CVE Checker

Command-line tool untuk mengecek CVE (Common Vulnerabilities and Exposures) pada server. Aplikasi ini mendeteksi OS dan package yang terinstall secara otomatis, lalu mencari vulnerability berdasarkan data dari **NIST NVD API**.

## Fitur

- **Deteksi Otomatis** — Mendeteksi OS dan package manager secara otomatis (dpkg, rpm, apk, brew, pip)
- **Pencarian CVE** — Query ke NIST NVD API v2.0 untuk data CVE terbaru
- **Solusi Perbaikan** — Menampilkan versi perbaikan dan perintah upgrade otomatis
- **Workaround** — Saran mitigasi sementara berdasarkan jenis vulnerability
- **Multi Bahasa** — Mendukung English dan Indonesia (auto-detect dari locale system)
- **Rate Limiting** — Mengatur limit API agar tidak terkena block

## Instalasi

### Build dari Source

```bash
git clone <repo-url>
cd cvechecker
go build -o cvechecker ./cmd/
```

### Requirements

- Go 1.21 atau lebih baru
- Akses internet (untuk query NVD API)
- Package manager terdeteksi: brew (macOS), dpkg/apt (Debian/Ubuntu), rpm/yum (CentOS/RHEL), apk (Alpine), pip3

## Penggunaan

### Dasar

```bash
# Tampilkan bantuan
./cvechecker help

# Cek CVE untuk satu package
./cvechecker check -p openssl -v 1.1.1

# Scan semua package di server
./cvechecker scan
```

### Dengan Solusi

```bash
# Tampilkan perintah upgrade untuk CVE yang ditemukan
./cvechecker check -p openssl -v 1.1.1 -fix

# Scan server + solusi
./cvechecker scan -fix
```

### Multi Bahasa

```bash
# Auto-detect dari locale system (default)
./cvechecker check -p nginx -fix

# Force English
./cvechecker -lang en check -p nginx -fix

# Force Indonesia
./cvechecker -lang id check -p nginx -fix
```

### Dengan API Key

NVD API key diperlukan untuk rate limit lebih tinggi. Dapatkan gratis di https://nvd.nist.gov/account/request-an-api-key

```bash
# Set API key sekali, otomatis dipakai setiap scan/check
./cvechecker config set-key YOUR_API_KEY

# Setelah itu, cukup jalankan scan tanpa flag -key
./cvechecker scan -fix

# Override via flag jika perlu pakai key berbeda
./cvechecker scan -fix -key OTHER_API_KEY
```

## Konfigurasi API Key

### Dapatkan API Key

NVD API key gratis dan diperlukan untuk rate limit lebih tinggi (50 request/30 detik vs 5 request/30 detik tanpa key).

**Cara mendapatkan API key:**

1. Buka https://nvd.nist.gov/account/request-an-api-key
2. Klik **"Request an API Key"**
3. Isi form registrasi:
   - Email address
   - First name
   - Last name
   - Organization name (boleh personal)
4. Cek email untuk verifikasi
5. Setelah verifikasi, API key akan dikirim ke email
6. Simpan API key ke config:

```bash
./cvechecker config set-key YOUR_API_KEY
```

> **Catatan:** API key biasanya aktif dalam beberapa menit setelah registrasi. Jika belum aktif, tunggu beberapa saat lalu coba lagi.

### Simpan API Key

```bash
./cvechecker config set-key YOUR_API_KEY
```

API key disimpan di `~/.config/cvechecker/config.json` dan otomatis dipakai untuk semua perintah selanjutnya.

### Lihat Config

```bash
./cvechecker config show
```

Output:

```
[Configuration]
  Config File : /Users/username/.config/cvechecker/config.json
  NVD API Key : abc****ef456
```

### Ganti API Key

```bash
./cvechecker config set-key NEW_API_KEY
```

### Hapus API Key

```bash
./cvechecker config reset
```

### Lokasi Config File

| OS | Lokasi |
|----|--------|
| macOS | `~/.config/cvechecker/config.json` |
| Linux | `~/.config/cvechecker/config.json` |

### Prioritas API Key

Jika API key ditulis di flag `-key` dan di config file, flag `-key` lebih diutamakan.

```bash
# Pakai key dari config (abc****ef456)
./cvechecker scan -fix

# Override dengan flag (XYZ****789)
./cvechecker scan -fix -key XYZ123ABC456DEF789
```

## Flag Tersedia

### Global Options

| Flag | Keterangan |
|------|------------|
| `-lang` | Force bahasa: `en` atau `id` (default: auto-detect) |

### Scan Command

| Flag | Keterangan |
|------|------------|
| `-limit` | Maksimal package yang di-scan (default: 50) |
| `-key` | NVD API key untuk rate limit lebih tinggi |
| `-verbose` | Tampilkan semua package yang terdeteksi |
| `-fix` | Tampilkan perintah upgrade untuk CVE yang ditemukan |

### Check Command

| Flag | Keterangan |
|------|------------|
| `-p` | Nama package (wajib) |
| `-v` | Versi package (opsional) |
| `-key` | NVD API key |
| `-fix` | Tampilkan perintah upgrade |

## Contoh Output

### Tanpa Solusi

```
[⚠ Vulnerability Results]
────────────────────────────────────────────────────────────

📦 openssl (1.1.1) (5 CVEs)
  HIGH      CVE-2021-3711 (Score: 9.8)
    In order to decrypt SM2 encrypted data an application is expected to...
    https://nvd.nist.gov/vuln/detail/CVE-2021-3711

[Summary]
  🔴 Critical : 1
  🟠 High     : 4
  📊 Total    : 5
```

### Dengan Solusi (-fix)

```
[⚠ Vulnerability Results]
────────────────────────────────────────────────────────────

📦 openssl (1.1.1) (5 CVEs)
  CRITICAL  CVE-2021-3711 (Score: 9.8)
    In order to decrypt SM2 encrypted data an application is expected to...
    https://nvd.nist.gov/vuln/detail/CVE-2021-3711
    🔧 Fix Version: 1.1.1l
    💡 Run: brew upgrade openssl
    📋 Solution: Upgrade to version 1.1.1l or later
    🔗 Patches:
       • https://www.openssl.org/news/secadv/20210824.txt
    ⚠ Workaround: Enable ASLR and DEP on affected systems

[Summary]
  🔴 Critical : 1
  🟠 High     : 4
  📊 Total    : 5
```

### Output Indonesia (-lang id)

```
📦 openssl (1.1.1) (5 CVEs)
  CRITICAL  CVE-2021-3711 (Score: 9.8)
    🔧 Versi Perbaikan: 1.1.1l
    💡 Jalankan: brew upgrade openssl
    📋 Solusi: Upgrade ke versi 1.1.1l atau yang lebih baru
    🔗 Patch Tersedia:
       • https://www.openssl.org/news/secadv/20210824.txt
    ⚠ Solusi Sementara: Aktifkan ASLR dan DEP di sistem yang terdampak

[Ringkasan]
  🔴 Kritis : 1
  🟠 Tinggi     : 4
  📊 Total    : 5
```

## Struktur Project

```
cvechecker/
├── cmd/main.go                          # CLI entry point
├── internal/
│   ├── models/models.go                 # Data structures
│   ├── detector/detector.go             # OS & package detection
│   ├── nvd/client.go                    # NIST NVD API client
│   ├── solution/solution.go             # Upgrade command generator
│   ├── formatter/formatter.go           # Terminal output
│   ├── config/config.go                 # Config file manager
│   └── i18n/                            # Internationalization
│       ├── i18n.go                      # Language detection
│       └── labels.go                    # Translations (EN/ID)
├── go.mod
└── cvechecker                           # Binary
```

## Package Manager yang Didukung

| Package Manager | OS |
|-----------------|-----|
| `brew` | macOS |
| `dpkg` / `apt` | Debian, Ubuntu |
| `rpm` / `yum` | CentOS, RHEL |
| `apk` | Alpine Linux |
| `pip3` | Python (cross-platform) |

## Rate Limit

Tanpa API key, NVD API membatasi **5 request per 30 detik**. Dengan API key, limit naik menjadi **50 request per 30 detik**.

Aplikasi otomatis menambahkan delay 6 detik antar request tanpa API key untuk menghindari rate limit.

## License

MIT
