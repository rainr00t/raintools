pattern = """{Fore.GREEN}
     •       ┓    Raintools v0.1 by rainr00t.
 ┏┓┏┓┓┏┓╋┏┓┏┓┃┏   For nothing but educational purposes.
 ┛ ┗┻┗┛┗┗┗┛┗┛┗┛   Select something below:
-------------------------------------------------------- 
1) WHOIS       | 5) PortScan | 9) ComingSoon
2) Traceroute  | 6) SndPacks | 10) ComingSoon
3) DomaintoIP  | 7)          | 11) ComingSoon
4) IPtoDomain  | 8)          | 12) ComingSoon

"""
import socket
import time
from colorama import Fore, Back, Style
import scapy.all as scapy
import struct
print(pattern)
def get_whois_data(domain_name):

  try:

    port = 43

    whois_server = socket.gethostbyname("whois.iana.org")


    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    sock.connect((whois_server, port))

    query = f"{domain_name}\r\n".encode()
    sock.sendall(query)

    whois_data = b""
    while True:
      data = sock.recv(1024)
      if not data:
        break
      whois_data += data

    sock.close()

    return whois_data.decode()
  except Exception as e:
    print(f"Error retrieving whois data: {e}")
    return None

def get_hostname_from_ip(ip_address):
 
  try:
    hostname = socket.gethostbyaddr(ip_address)[0]
    return hostname
  except socket.herror:
    return None

def traceroute(dest_addr, max_hops=30, timeout=2):
    if "." not in dest_addr and ":" not in dest_addr:
        try:
            dest_addr = socket.gethostbyname(dest_addr)
        except socket.gaierror:
            print(f"Error: Unable to resolve hostname '{dest_addr}'")
            return
    
    for ttl in range(1, max_hops+1):
        try:
            skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            skt.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            skt.connect((dest_addr, 80))
            print(f"{ttl}\t{skt.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)}\t{dest_addr}")
            skt.close()
        except socket.error:
            print(f"{ttl}\t*-*\t{dest_addr}")

def get_hostname(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "N/A"

def get_ip_addresses(domain):
    try:
        ip_addresses = socket.gethostbyname_ex(domain)[2]
        return ip_addresses
    except socket.gaierror as e:
        return f"Error: {e}"



def is_port_open(host, port):
    """
    determine whether `host` has the `port` open
    """

    s = socket.socket()
    try:

        s.connect((host, port))
   
        s.settimeout(2)
    except:
    
        return False
    else:

        return True
    

def send_packet(host, message, interval, num_packets):

    s = socket.socket()


    s.connect((host, 80))


    for i in range(num_packets):
        s.send(message.encode())
        a = 0
        print(i+1 , "package sent sufccessfully")
        time.sleep(interval)

  
    s.close()

fruit = input("Select a number: ")

if fruit == "1":   

    print("running WHOIS tool...")
    domain_name = input("Domain: ")
    whois_data = get_whois_data(domain_name)

    if whois_data:
        print(whois_data)
    else:
        print("Failed to retrieve whois data.")


elif fruit == "2":
    print("If you're getting an error, try running code in an admin console.")
    destination = input("Enter the destination IP or domain: ")
    traceroute(destination)

elif fruit == "3":
   domain_name = input("Enter the domain name: ")
   ip_addresses = get_ip_addresses(domain_name)
   if isinstance(ip_addresses, list):
        print(f"\nIP Addresses for {domain_name}:")
        for ip in ip_addresses:
            print(ip)
   else:
    print(ip_addresses)
    
elif fruit == "4":

    ip_address = input("Enter an IP address:")
    hostname = get_hostname_from_ip(ip_address)

    if hostname:
        print(f"Hostname for {ip_address}: {hostname}")
    else:
        print(f"No hostname found for {ip_address}.")
elif fruit == "5":
  

    host = input("Enter the host (IP address or website): ")


    start_port = int(input("Enter the starting port: "))
    end_port = int(input("Enter the ending port: "))
    print("Please wait for a while, it may look like it is frozen but it is not.")

    for port in range(start_port, end_port+1):
        if is_port_open(host, port):
            print(f"{Fore.GREEN}[+] {host}:{port} is open{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] {host}:{port} is closed{Style.RESET_ALL}", end="\r")

elif fruit == "6":
 
    host = input("Enter the host (IP address or website): ")


    message = input("Enter the message: ")


    interval = float(input("Enter the interval between packets (in seconds): "))

  
    num_packets = int(input("Enter the number of packets to send: "))

    send_packet(host, message, interval, num_packets)

    print(f"Sent {num_packets} packets to {host} with message: {message} and interval: {interval} seconds")
else:
    print("Try Again.")



