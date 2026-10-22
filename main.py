import argparse
import sys
import os
import json
import pyshark
from collections import defaultdict

def analyze_pcap(file_path, threshold=5, output_file=None):
    """
    Analyzes a PCAP/PCAPNG file for FTP brute-force attacks, 
    extracts targeted usernames, and detects successful breaches.
    """
    if not os.path.exists(file_path):
        print(f"[-] Error: File '{file_path}' not found.")
        sys.exit(1)
        
    print(f"[*] Analyzing {file_path} for FTP brute-force attacks...")
    
    # Data structure to track attacker activity
    # Format: { 'ip': {'failed_attempts': 0, 'usernames': set(), 'breached': False} }
    attack_data = defaultdict(lambda: {'failed_attempts': 0, 'usernames': set(), 'breached': False})
    
    try:
        capture = pyshark.FileCapture(file_path, display_filter='ftp')
        
        for packet in capture:
            if not hasattr(packet, 'ftp'):
                continue
            
            # Track targeted usernames (Client -> Server)
            if hasattr(packet.ftp, 'request_command') and packet.ftp.request_command == 'USER':
                attacker_ip = packet.ip.src
                username = packet.ftp.request_arg
                attack_data[attacker_ip]['usernames'].add(username)
                
            # Track authentication responses (Server -> Client)
            if hasattr(packet.ftp, 'response_code'):
                attacker_ip = packet.ip.dst # Server responds TO the attacker
                
                # 530: Not logged in (Failed)
                if packet.ftp.response_code == '530':
                    attack_data[attacker_ip]['failed_attempts'] += 1
                
                # 230: User logged in (Success)
                elif packet.ftp.response_code == '230':
                    if attack_data[attacker_ip]['failed_attempts'] > 0:
                        attack_data[attacker_ip]['breached'] = True

        capture.close()
        generate_report(attack_data, threshold, output_file)
            
    except Exception as e:
        print(f"[-] Error during analysis: {e}")

def generate_report(attack_data, threshold, output_file):
    """Generates console output and optional JSON report."""
    print("\n" + "="*30 + " ANALYSIS REPORT " + "="*30)
    
    report_results = []
    attack_detected = False
    
    for ip, data in attack_data.items():
        if data['failed_attempts'] >= threshold:
            attack_detected = True
            usernames_list = list(data['usernames'])
            
            print(f"[!] BRUTE-FORCE DETECTED from IP: {ip}")
            print(f"    - Failed attempts: {data['failed_attempts']}")
            print(f"    - Targeted usernames: {', '.join(usernames_list) if usernames_list else 'Unknown'}")
            
            if data['breached']:
                print("    - [CRITICAL] SUCCESSFUL LOGIN DETECTED AFTER BRUTE-FORCE!")
            print("-" * 75)
            
            report_results.append({
                "attacker_ip": ip,
                "failed_attempts": data['failed_attempts'],
                "targeted_usernames": usernames_list,
                "successful_breach": data['breached']
            })
            
    if not attack_detected:
        print("[+] No brute-force attacks detected matching the criteria.")
        
    if output_file and report_results:
        with open(output_file, 'w') as f:
            json.dump(report_results, f, indent=4)
        print(f"\n[+] Detailed report saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="FTP Brute-Force Detector")
    parser.add_argument("-f", "--file", required=True, help="Path to the .pcap/.pcapng file")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Detection threshold (default: 5)")
    parser.add_argument("-o", "--output", help="Save report to JSON file")
    
    args = parser.parse_args()
    analyze_pcap(args.file, args.threshold, args.output)

if __name__ == "__main__":
    main()