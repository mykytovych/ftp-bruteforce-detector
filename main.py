import argparse
import sys
import os
import pyshark

def analyze_pcap(file_path):
    """
    Analyzes a PCAP/PCAPNG file for FTP brute-force attacks.
    
    Args:
        file_path (str): The path to the network capture file.
    """
    if not os.path.exists(file_path):
        print(f"[-] Error: File '{file_path}' not found.")
        sys.exit(1)
        
    print(f"[*] Starting analysis on {file_path}...")
    
    # TODO: Implement pyshark logic to filter and analyze FTP traffic
    # This is a placeholder for future logic (Section 2.3 of the plan)
    
    print("[*] Analysis complete.")

def main():
    """
    Main entry point for the CLI application.
    Sets up argument parsing and triggers the analysis.
    """
    parser = argparse.ArgumentParser(
        description="FTP Brute-Force Detector: Analyze PCAP files for FTP attacks."
    )
    
    parser.add_argument(
        "-f", "--file", 
        required=True, 
        help="Path to the .pcap or .pcapng file"
    )
    
    args = parser.parse_args()
    
    analyze_pcap(args.file)

if __name__ == "__main__":
    main()