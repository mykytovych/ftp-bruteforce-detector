import os
from scapy.all import IP, TCP, Raw, wrpcap

def generate_mock_attack(filename):
    """
    Generates a mock PCAP file containing FTP 530 responses 
    to simulate a brute-force attack.
    """
    packets = []
    attacker_ip = "192.168.1.105"
    server_ip = "192.168.1.10"

    # Generate 8 failed login attempts (above our default threshold of 5)
    for i in range(8):
        # Simulating FTP server response to a failed login
        ftp_payload = b"530 Login incorrect.\r\n"
        pkt = IP(src=server_ip, dst=attacker_ip) / TCP(sport=21, dport=40000+i) / Raw(load=ftp_payload)
        packets.append(pkt)

    wrpcap(filename, packets)
    print(f"[*] Generated test file '{filename}' with 8 failed attempts from {attacker_ip}")

if __name__ == "__main__":
    os.makedirs("tests", exist_ok=True)
    generate_mock_attack("tests/mock_attack.pcap")