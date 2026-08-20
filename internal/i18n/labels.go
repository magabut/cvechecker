package i18n

import "fmt"

var Labels = struct {
	FixVersion    func() string
	Run           func() string
	Solution      func() string
	Patches       func() string
	Workaround    func() string
	UpgradeTo     func(string) string
	NoCVEFound    func() string
	OSInfo        func() string
	PackageDetect func() string
	Checking      func(string, string) string
	Warning       func() string
	Summary       func() string
	Critical      func() string
	High          func() string
	Medium        func() string
	Low           func() string
	Total         func() string
	NoPackages    func() string
	RestrictNet   func() string
	MonitorAvail  func() string
	ReviewPerms   func() string
	EnableCSP     func() string
	ValidateInput func() string
	EnableASLR    func() string
	ReviewVendor  func() string
}{
	FixVersion:    func() string { return T("Fix Version", "Versi Perbaikan") },
	Run:           func() string { return T("Run", "Jalankan") },
	Solution:      func() string { return T("Solution", "Solusi") },
	Patches:       func() string { return T("Patches", "Patch Tersedia") },
	Workaround:    func() string { return T("Workaround", "Solusi Sementara") },
	UpgradeTo:     func(v string) string { return fmt.Sprintf(T("Upgrade to version %s or later", "Upgrade ke versi %s atau yang lebih baru"), v) },
	NoCVEFound:    func() string { return T("No CVEs found for scanned packages", "Tidak ditemukan CVE untuk package yang di-scan") },
	OSInfo:        func() string { return T("OS Information", "Informasi Sistem Operasi") },
	PackageDetect: func() string { return T("Detecting installed packages...", "Mendeteksi package yang terinstall...") },
	Checking:      func(a, b string) string { return fmt.Sprintf(T("Checking %s %s...", "Mengecek %s %s..."), a, b) },
	Warning:       func() string { return T("Warning", "Peringatan") },
	Summary:       func() string { return T("Summary", "Ringkasan") },
	Critical:      func() string { return T("Critical", "Kritis") },
	High:          func() string { return T("High", "Tinggi") },
	Medium:        func() string { return T("Medium", "Sedang") },
	Low:           func() string { return T("Low", "Rendah") },
	Total:         func() string { return T("Total", "Total") },
	NoPackages:    func() string { return T("No packages found", "Tidak ada package ditemukan") },
	RestrictNet:   func() string { return T("Restrict network access to affected service until patched", "Batasi akses jaringan ke service yang terdampak sampai di-patch") },
	MonitorAvail:  func() string { return T("Monitor service availability and implement rate limiting", "Pantau ketersediaan service dan implementasikan rate limiting") },
	ReviewPerms:   func() string { return T("Review and restrict user permissions on affected systems", "Tinjau dan batasi permission user di sistem yang terdampak") },
	EnableCSP:     func() string { return T("Enable Content Security Policy (CSP) headers", "Aktifkan header Content Security Policy (CSP)") },
	ValidateInput: func() string { return T("Validate and sanitize all user inputs; use parameterized queries", "Validasi dan sanitasi semua input user; gunakan parameterized query") },
	EnableASLR:    func() string { return T("Enable ASLR and DEP on affected systems", "Aktifkan ASLR dan DEP di sistem yang terdampak") },
	ReviewVendor:  func() string { return T("Review the vendor advisory for specific mitigation steps", "Tinjau advisory vendor untuk langkah mitigasi spesifik") },
}
