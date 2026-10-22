import argparse
import sys
import os
import pyshark
from collections import defaultdict

def analyze_pcap(file_path, threshold=5):
    """
    Analyzes a PCAP/PCAPNG file for FTP brute-force attacks.
    
    Args:
        file_path (str): The path to the network capture file.
        threshold (int): Number of failed attempts to be considered an attack.
    """
    if not os.path.exists(file_path):
        print(f"[-] Error: File '{file_path}' not found.")
        sys.exit(1)
        
    print(f"[*] Analyzing {file_path} for FTP brute-force attacks...")
    
    try:
        # Use display_filter to only parse FTP traffic, significantly speeding up the process
        capture = pyshark.FileCapture(file_path, display_filter='ftp')
        
        # Dictionary to store failed attempts per IP
        failed_attempts = defaultdict(int)
        
        for packet in capture:
            if hasattr(packet, 'ftp') and hasattr(packet.ftp, 'response_code'):
                # FTP response code 530 means "Not logged in" (failed authentication)
                if packet.ftp.response_code == '530':
                    # The destination IP of the server's 530 response is the attacker's IP
                    attacker_ip = packet.ip.dst
                    failed_attempts[attacker_ip] += 1
                    
        capture.close()
        
        # --- Generate Report (Section 2.4 of the plan) ---
        print("\n=== Analysis Report ===")
        attack_detected = False
        
        for ip, count in failed_attempts.items():
            if count >= threshold:
                print(f"[!] BRUTE-FORCE DETECTED: Attacker IP: {ip} | Failed attempts: {count}")
                attack_detected = True
                
        if not attack_detected:
            print("[+] No brute-force attacks detected in this file.")
            
    except Exception as e:
        print(f"[-] Error during analysis: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="FTP Brute-Force Detector: Analyze PCAP files for FTP attacks."
    )
    
    parser.add_argument(
        "-f", "--file", 
        required=True, 
        help="Path to the .pcap or .pcapng file"
    )
    
    parser.add_argument(
        "-t", "--threshold", 
        type=int, 
        default=5, 
        help="Number of failed attempts to trigger detection (default: 5)"
    )
    
    args = parser.parse_args()
    analyze_pcap(args.file, args.threshold)

if __name__ == "__main__":
    main()