import os
from scapy.all import Ether, IP, TCP, Raw, wrpcap

def generate_full_mock_attack(filename):
    """
    Generates a realistic mock PCAP with Ethernet frames, 
    FTP requests (USER), and responses (530/230).
    """
    packets = []
    attacker_ip = "192.168.1.105"
    server_ip = "192.168.1.10"
    
    users = ["admin", "root", "test", "user", "guest", "administrator"]
    
    # 1. Generate 6 failed login attempts
    for i, user in enumerate(users):
        # Adding Ether() makes it a valid MAC-layer frame that Wireshark parses correctly
        req = Ether() / IP(src=attacker_ip, dst=server_ip) / TCP(sport=40000+i, dport=21) / Raw(load=f"USER {user}\r\n".encode())
        packets.append(req)
        
        res = Ether() / IP(src=server_ip, dst=attacker_ip) / TCP(sport=21, dport=40000+i) / Raw(load=b"530 Not logged in.\r\n")
        packets.append(res)
        
    # 2. Generate 1 successful login attempt
    req_succ = Ether() / IP(src=attacker_ip, dst=server_ip) / TCP(sport=40010, dport=21) / Raw(load=b"USER admin\r\n")
    packets.append(req_succ)
    
    res_succ = Ether() / IP(src=server_ip, dst=attacker_ip) / TCP(sport=21, dport=40010) / Raw(load=b"230 User logged in.\r\n")
    packets.append(res_succ)

    wrpcap(filename, packets)
    print(f"[*] Generated full test file '{filename}' with Ethernet layer.")

if __name__ == "__main__":
    os.makedirs("tests", exist_ok=True)
    generate_full_mock_attack("tests/mock_attack.pcap")