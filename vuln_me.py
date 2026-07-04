#!/usr/bin/env python3
import socket
import subprocess
import sys
import threading
from datetime import datetime
import os
import re

def print_banner():
    print("""
    =============================================
    |     Simple Linux Vuln Scanner (Python)    |
    |           For personal use only           |
    =============================================
    """)

def is_root():
    if os.geteuid() != 0:
        print("[-] Script ini butuh root privileges.")
        print("    Jalankan dengan: sudo python3 vuln_scanner.py")
        return False
    return True

def get_address_family(target):
    """Deteksi apakah IPv4 atau IPv6"""
    try:
        # Coba IPv6
        if re.match(r'^\[?([0-9a-fA-F:]+)\]?$', target):
            return socket.AF_INET6
        # Coba IPv4
        socket.inet_pton(socket.AF_INET, target)
        return socket.AF_INET
    except:
        try:
            # Resolve hostname
            info = socket.getaddrinfo(target, None)
            return info[0][0]  # AF_INET atau AF_INET6
        except:
            return socket.AF_INET  # default

def validate_target(target):
    """Validasi IPv4, IPv6, atau hostname"""
    if not target:
        return False
    
    # IPv4
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
        try:
            socket.inet_pton(socket.AF_INET, target)
            return True
        except:
            pass
    
    # IPv6
    if re.match(r'^[0-9a-fA-F:]+$', target.replace('[', '').replace(']', '')):
        try:
            socket.inet_pton(socket.AF_INET6, target.replace('[', '').replace(']', ''))
            return True
        except:
            pass
    
    # Hostname
    if re.match(r'^[a-zA-Z0-9.-]+$', target):
        try:
            socket.gethostbyname(target)
            return True
        except:
            pass
    return False

def port_scan(target, start_port=1, end_port=1024):
    open_ports = []
    family = get_address_family(target)
    print(f"[+] Memulai port scan pada {target} ({start_port}-{end_port}) - {'IPv6' if family == socket.AF_INET6 else 'IPv4'}")
    print(f"[+] Scan dimulai: {datetime.now()}")
    
    def scan_port(port):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"[+] Port {port} OPEN")
        except:
            pass
    
    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()
        
        if len(threads) >= 100:
            for t in threads:
                t.join()
            threads = []
    
    for t in threads:
        t.join()
    
    print(f"[+] Port scan selesai: {datetime.now()}")
    return open_ports

def grab_banner(target, port):
    family = get_address_family(target)
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((target, port))
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else "No banner"
    except:
        return None

# Fungsi check_vulnerabilities, linux_system_checks, export_to_html tetap sama seperti sebelumnya
def check_vulnerabilities(banners, vuln_db_path="vuln_db.txt"):
    if not os.path.exists(vuln_db_path):
        with open(vuln_db_path, "w") as f:
            f.write("vsftpd 2.3.4\nOpenSSH_4\nApache/2.2\n")
        print("[+] vuln_db.txt dibuat otomatis.")
    
    vulnerable = []
    with open(vuln_db_path, "r") as f:
        vulns = [line.strip().lower() for line in f.readlines() if line.strip()]
    
    for port, banner in banners.items():
        banner_lower = banner.lower()
        for vuln in vulns:
            if vuln in banner_lower:
                vulnerable.append((port, banner, vuln))
    return vulnerable

def linux_system_checks():
    print("\n[+] Melakukan pemeriksaan sistem Linux...")
    checks = [
        ("Kernel Version", "uname -a"),
        ("Paket yang perlu update", "apt list --upgradable 2>/dev/null | head -20"),
        ("World-writable files", "find / -type f -perm -002 2>/dev/null | head -10"),
        ("Running Services", "systemctl list-units --type=service --state=running | head -15"),
    ]
    results = {}
    for desc, cmd in checks:
        try:
            result = subprocess.getoutput(cmd)
            results[desc] = result if result.strip() else "No output"
        except:
            results[desc] = "Command failed"
    return results

def export_to_html(target, open_ports, banners, vulns, system_checks=None, filename="scan_report.html"):
    html = f"""<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>Vuln Scan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f4f4f4; }}
        h1, h2 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        .vuln {{ background-color: #ffdddd; }}
        pre {{ background: #eee; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>Laporan Vulnerability Scan</h1>
    <p><strong>Target:</strong> {target}</p>
    <p><strong>Waktu:</strong> {datetime.now()}</p>
    
    <h2>Port Terbuka</h2>
    <table>
        <tr><th>Port</th><th>Banner</th></tr>
"""
    for port in open_ports:
        banner = banners.get(port, "Unknown")
        html += f"        <tr><td>{port}</td><td>{banner}</td></tr>\n"
    
    html += """    </table>
    
    <h2>Vulnerability Findings</h2>
"""
    if vulns:
        html += '<table><tr><th>Port</th><th>Banner</th><th>Vuln Match</th></tr>'
        for p, b, v in vulns:
            html += f'<tr class="vuln"><td>{p}</td><td>{b}</td><td>{v}</td></tr>'
        html += '</table>'
    else:
        html += '<p>Tidak ditemukan vulnerability yang cocok.</p>'
    
    if system_checks:
        html += '<h2>System Checks</h2><table><tr><th>Check</th><th>Result</th></tr>'
        for k, v in system_checks.items():
            html += f'<tr><td>{k}</td><td><pre>{v}</pre></td></tr>'
        html += '</table>'
    
    html += """
    <hr>
    <p><small>Generated by Simple Linux Vuln Scanner • Gunakan untuk tujuan etis saja</small></p>
</body>
</html>"""
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Laporan berhasil diekspor ke: {filename}")

def main():
    print_banner()
    if not is_root():
        sys.exit(1)
    
    while True:
        target = input("[+] Masukkan target IP atau hostname (contoh: 127.0.0.1, ::1, atau localhost): ").strip()
        if validate_target(target):
            print(f"[+] Target valid: {target}")
            break
        else:
            print("[-] Input tidak valid. Masukkan IP IPv4/IPv6 atau hostname yang valid.")
            retry = input("Coba lagi? (y/n): ").strip().lower()
            if retry != 'y':
                print("[-] Scan dibatalkan.")
                sys.exit(1)
    
    print("\n[1] Port Scan + Banner + Vuln Check + HTML Report")
    print("[2] Linux System Vulnerability Check + HTML Report")
    choice = input("[+] Pilih (1/2): ").strip()
    
    open_ports = []
    banners = {}
    vulns = []
    system_checks = None
    
    if choice == "1":
        try:
            start = int(input("[+] Start port (default 1): ") or 1)
            end = int(input("[+] End port (default 1024): ") or 1024)
            if not (1 <= start <= end <= 65535):
                print("[-] Range port tidak valid.")
                sys.exit(1)
        except ValueError:
            print("[-] Input port harus angka.")
            sys.exit(1)
        
        open_ports = port_scan(target, start, end)
        
        print("\n[+] Mengambil banner...")
        for port in open_ports:
            banner = grab_banner(target, port)
            if banner:
                banners[port] = banner
                print(f"[+] Port {port}: {banner[:80]}...")
        
        print("\n[+] Mengecek vulnerability...")
        vulns = check_vulnerabilities(banners)
        if vulns:
            for p, b, v in vulns:
                print(f"[!!] VULNERABLE → Port {p}: {v}")
    
    elif choice == "2":
        system_checks = linux_system_checks()
    else:
        print("[-] Pilihan tidak valid.")
        return
    
    export_to_html(target, open_ports, banners, vulns, system_checks)
    print("\n[+] Scan selesai! Buka file HTML untuk laporan lengkap.")

if __name__ == "__main__":
    main()
