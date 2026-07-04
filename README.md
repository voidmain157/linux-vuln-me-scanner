# linux-vuln-me-scanner
A simple yet powerful Python tool for scanning open ports, grabbing service banners, detecting known vulnerabilities, and performing basic Linux system security audits. Supports IPv4 &amp; IPv6.
Alat scanning vulnerability Linux berbasis Python. Dilengkapi port scanner, banner grabbing, dan system check. Hanya untuk penggunaan pribadi dan edukasi.

# Linux Vulnerability Scanner (Python)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

Tool scanning vulnerability sederhana berbasis Python yang terinspirasi dari Nmap. Dirancang khusus untuk *penggunaan pribadi* pada sistem Linux.

## ✨ Fitur

- *Port Scanner* multi-thread (support IPv4 & IPv6)
- *Banner Grabbing* otomatis
- *Vulnerability Detection* berdasarkan banner service
- *Linux System Audit* (kernel, paket update, permission, services, dll)
- *Export Laporan* ke HTML yang rapi
- Validasi input IP/Hostname
- Ringan & tidak bergantung library eksternal

## 📸 Preview Laporan
![HTML Report](https://via.placeholder.com/800x400?text=HTML+Report+Preview)  
(Laporan HTML otomatis dibuat setelah scan)

## 🚀 Cara Penggunaan

### Persiapan
```bash
# Beri izin eksekusi
chmod +x vuln_scanner.py
python vuln_scanner.py
python3 vuln.scanner.py
