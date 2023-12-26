import asyncio
from scapy.all import ARP, Ether, srp
import psutil
import csv
import time
import socket
from typing import Dict, Tuple

async def get_mac(ip: str) -> str:
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    result = await asyncio.get_event_loop().run_in_executor(None, srp, packet, None, 2, False)
    ans, _ = result[0]

    return ans[0][1].hwsrc

async def get_speed() -> Tuple[int, int]:
    interface = list(psutil.net_if_stats().keys())[0]

    stats = psutil.net_io_counters(pernic=True)[interface]
    upload_speed = stats.bytes_sent
    download_speed = stats.bytes_recv

    return upload_speed, download_speed

async def save_to_csv(data: Dict[str, Tuple[str, int, int]]):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    filename = "network_data.csv"

    fieldnames = ['Timestamp', 'IP', 'MAC', 'Upload Speed', 'Download Speed']

    with open(filename, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if csvfile.tell() == 0:
            writer.writeheader()

        for ip, (mac, upload_speed, download_speed) in data.items():
            writer.writerow({'Timestamp': timestamp, 'IP': ip, 'MAC': mac, 'Upload Speed': str(upload_speed), 'Download Speed': str(download_speed)})

    print(f"Data appended to {filename}")

async def scan_network(ip_range: str):
    devices = {}

    try:
        result = await asyncio.get_event_loop().run_in_executor(None, srp, Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), None, 2, False)
        ans, _ = result[0]

        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc
            upload_speed, download_speed = await get_speed()
            devices[ip] = (mac, upload_speed, download_speed)
    
    except Exception as e:
        print(f"An error occurred: {e}")

    return devices

async def main() -> None:
    interfaces = psutil.net_if_addrs()
    ip_range = None

    # Retrieve the IP range from the first interface with an IPv4 address
    for interface_name, interface_addresses in interfaces.items():
        for address in interface_addresses:
            if address.family == socket.AF_INET:
                ip_address = address.address
                subnet_mask = address.netmask

                ip_parts = ip_address.split('.')
                subnet_parts = subnet_mask.split('.')
                network_parts = [str(int(ip_parts[i]) & int(subnet_parts[i])) for i in range(4)]
                network_address = '.'.join(network_parts)

                subnet_bits = sum([bin(int(x)).count('1') for x in subnet_parts])

                ip_range = f"{network_address}/{subnet_bits}"
                break

        if ip_range:
            break

    if not ip_range:
        print("Unable to determine IP range. Please check your network configuration.")
        return

    while True:
        devices = await scan_network(ip_range)

        for ip, (mac, upload_speed, download_speed) in devices.items():
            print(f"Device: {ip} ({mac})")
            print(f"Upload speed: {upload_speed} bytes/sec")
            print(f"Download speed: {download_speed} bytes/sec")
            print()

        #await save_to_csv(devices)

        await asyncio.sleep(5)

if __name__ == '__main__':
    asyncio.run(main())