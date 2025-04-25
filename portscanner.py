Python 3.11.9 (tags/v3.11.9:de54cf5, Apr  2 2024, 10:12:12) [MSC v.1938 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license()" for more information.
import socket
import threading
from queue import Queue
from ipwhois import IPWhois
from datetime import datetime

# ========================
# Customize this banner
# ========================
def print_banner():
    banner = r"""
 ____                  _       ____                 
|  _ \ ___  ___   ___ | |_    / ___|  ___ __ _ _ __ 
| |_) / _ \/ __| / _ \| __|   \___ \ / __/ _` | '__|
|  __/ (_) \__ \| (_) | |_     ___) | (_| (_| | |   
|_|   \___/|___(_)___/ \__|___|____/ \___\__,_|_|   
                        |_____|                     
"""
    print(banner)

# ========================
# Port Scanner Class
# ========================
class PortScanner:
    def __init__(self, target, ports, thread_count=100):
        self.target = target
        self.ports = ports
        self.thread_count = thread_count
        self.queue = Queue()
        self.open_ports = []

    def resolve_domain(self):
        try:
            ip = socket.gethostbyname(self.target)
            print(f"[+] Resolved {self.target} to {ip}")
            return ip
...         except socket.gaierror:
...             print("[-] Domain resolution failed.")
...             return None
... 
...     def geo_ip_lookup(self, ip):
...         try:
...             obj = IPWhois(ip)
...             results = obj.lookup_rdap()
...             country = results['network']['country']
...             print(f"[+] IP Geolocation Country: {country}")
...         except Exception as e:
...             print(f"[-] Geo IP lookup failed: {e}")
... 
...     def scan_port(self, ip):
...         while not self.queue.empty():
...             port = self.queue.get()
...             try:
...                 with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
...                     s.settimeout(1)
...                     if s.connect_ex((ip, port)) == 0:
...                         print(f"[+] Port {port} is open")
...                         self.open_ports.append(port)
...             except Exception:
...                 pass
...             finally:
...                 self.queue.task_done()
... 
...     def run(self):
...         print_banner()
...         print(f"[*] Starting scan at {datetime.now()}")
...         ip = self.resolve_domain()
...         if not ip:
...             return
... 
...         self.geo_ip_lookup(ip)
... 
...         for port in self.ports:
...             self.queue.put(port)
... 
...         threads = []
...         for _ in range(self.thread_count):
...             t = threading.Thread(target=self.scan_port, args=(ip,))
...             t.daemon = True
...             threads.append(t)
...             t.start()
... 
...         self.queue.join()
...         print(f"\n[+] Scan complete. Open ports: {sorted(self.open_ports)}")
... 
... # ========================
... # Main Execution
... # ========================
... if __name__ == "__main__":
...     # Example: Scan ports 20-1024
...     target = input("Enter target (domain or IP): ")
...     ports = list(range(20, 1025))
...     scanner = PortScanner(target=target, ports=ports, thread_count=200)
...     scanner.run()
>>> [DEBUG ON]
>>> [DEBUG OFF]
